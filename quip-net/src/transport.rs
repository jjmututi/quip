//! QUIC transport binding for QUIP (spec §12).
//!
//! **Status:** M5 complete, plus M7 hardening — Endpoint, T0 handshake,
//! T1/T2/T3 stream I/O, per-stream dispatch, the §16 Key Claim exchange,
//! per-peer receive-side rate limiting (§19.4), the T1 SYNC stream state
//! machine (§11), per-peer backoff tracking (§19.4), and a per-connection
//! T2 stream cap.
//!
//! # Architecture
//!
//! The driver holds the QUIC connection and the *send* half of every
//! stream. Read halves are moved into per-stream tasks that feed a
//! shared `mpsc::Sender<Event>`. [`ConnectionDriver::poll`] drains the
//! receiver, returning whatever events are ready within
//! `POLL_TIMEOUT_MS`.
//!
//! Tasks hold clones of the `quinn::Connection`, so dropping the driver
//! would not by itself terminate them. The [`Drop`] impl for
//! `ConnectionDriver` aborts every task it spawned.
//!
//! # Lifecycle
//!
//! 1. `Connecting` — the driver has not yet exchanged the §4 handshake.
//! 2. `KeyClaimExchanging` — handshake done, Key Claims not yet
//!    exchanged.
//! 3. `Established` — handshake and Key Claim exchange both complete;
//!    T1/T2/T3 traffic flows.
//!
//! `poll_handshake` performs steps 1–2 and, on success, spawns the read
//! tasks and returns `[Event::ControlConnected]`. The caller does not
//! see the intermediate state; the first successful `poll` moves the
//! driver straight to `Established`.
//!
//! # Tier classification
//!
//! Inbound stream IDs are classified as:
//!
//! | ID | Tier |
//! |---|---|
//! | 0 | T0 (Control) |
//! | 4 | T1 (Sync) |
//! | anything else | T2 (Bulk) |
//!
//! This handles both client-initiated and server-initiated bulk streams
//! without a special case. [`crate::frame::StreamId::kind`] is stricter
//! and is intended for wire-format validation, not for driver dispatch.
//!
//! # Opening T1
//!
//! QUIC streams are created on the peer when the first `STREAM` frame
//! arrives, not when [`quinn::Connection::open_bi`] resolves. The
//! initiator therefore writes a no-op [`FlowFrame::Window`] on T1 right
//! after opening it, so the responder's `accept_bi` returns. The frame
//! is consumed silently by `route_message` — it produces no
//! application event. This matches the requirement documented on
//! `quinn::Connection::open_bi`: waiting on the `RecvStream` without
//! writing to `SendStream` never succeeds.
//!
//! # Key Claim exchange
//!
//! §16 steps 7–8: after the §4 handshake, each peer sends its
//! self-signed [`quip_core::messages::KeyClaim`] on T0 and waits
//! for the other's. The driver sends its own and reads the peer's inline,
//! before any read task is pawned, so the `announce_key` messages never
//! surface as [`Event::Frame`]s.
//!
//! **The driver does not verify the peer's signature.** Callers MUST
//! verify it themselves — against the `NodeId` in the claim, under their
//! own TOFU or rotation-chain policy — before treating the peer's
//! identity as established. [`ConnectionDriver::peer_key_claim`] returns
//! the raw claim for that purpose.
//!
//! # Rate limiting
//!
//! Once the Key Claim exchange completes, the driver rate-limits
//! inbound traffic per peer NodeId (§19.4). The general limit is
//! [`RateLimiterConfig::general`] — 1000 ops/min with a 100-op burst by
//! default. Pin gossip, spillover, relay discovery, and governance
//! verbs each have their own bucket; see `operation_kind_for`. T2
//! (bulk) frames are exempt: they are bounded by stream-level flow
//! control, and a multi-gigabyte transfer would blow past any
//! ops-per-minute budget.
//!
//! Pre-handshake traffic is unbounded: the driver has no peer NodeId to
//! key on, and the handshake itself is short and QUIC-bounded.
//!
//! **Enforcement is per-connection.** The driver's limiter holds
//! buckets for the one peer on this connection, so the effective limit
//! matches the spec for a single-connection peer. To enforce a shared
//! budget across many connections to the same NodeId, a caller would
//! need to share a limiter across drivers — which this driver does not
//! currently support. That is a known limitation of the first cut; a
//! follow-up can hoist the limiter above the driver.
//!
//! # T1 SYNC state machine
//!
//! The driver holds a [`crate::sync_stream::SyncStream`]
//! that tracks whether T1 is currently serving a request (§11). The
//! machine is fed inbound T1 request frames via
//! `SyncStream::classify_verb`, and returned to `Idle` by the next
//! successful T1 write while the machine is busy. The state is exposed
//! via [`ConnectionDriver::sync_stream`] for callers that want to gate
//! their own T1 writes on it.
//!
//! A caller that wants finer control than "any T1 write while busy is a
//! response" can drive the machine directly through the accessor and
//! ignore the driver's automatic transitions.
//!
//! # Backoff
//!
//! A [`crate::backoff::BackoffTracker`] records
//! consecutive protocol errors keyed by peer NodeId. The driver only
//! records; it does not act. The retry policy belongs to whichever layer
//! dials the connection, so the tracker is exposed via
//! [`ConnectionDriver::backoff`] rather than driven automatically.
//!
//! # T2 stream cap
//!
//! Inbound T2 streams are bounded by a per-connection semaphore of
//! `T2_MAX_STREAMS` permits. The permit is held for the lifetime of the
//! stream's read task, so a peer that opens more concurrent bulk streams
//! than the cap gets backpressure from QUIC until an existing stream
//! closes. This bounds the driver's per-connection stream bookkeeping.
//!
//! # Certificate handling
//!
//! QUIP has no WebPKI (§5). TLS is a confidentiality layer, and identity
//! is established by the Key Claim exchange, not by the TLS certificate.
//! The server's certificate is supplied by the caller; the client skips
//! certificate verification with an internal no-op verifier.

use crate::backoff::BackoffTracker;
use crate::conn::{Connection as QuipConnection, QuipNetConfig};
use crate::constants::{
    ALPN_QUIP, CTRL_STREAM_ID, MAX_DGRAM_BYTES, SYNC_STREAM_ID, T2_MAX_STREAMS,
};
use crate::error::{Error, Result};
use crate::flow::{dispatch_flow, FlowFrame};
use crate::frame::{self, Tier};
use crate::handshake::Capabilities;
use crate::message::{self, Message};
use crate::rate::{OperationKind, RateLimiter, RateLimiterConfig};
use crate::sync_stream::{SyncEvent, SyncStream};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use quip_core::cbor::CborValue;
use quip_core::dvv::NodeId;
use quip_core::messages::KeyClaim;
use quip_core::time::Timestamp;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::Endpoint as QuinnEndpoint;
use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;

/// Maximum handshake size we will buffer before rejecting.
const MAX_HANDSHAKE_BYTES: usize = 4_096;

/// Bounded wait in [`ConnectionDriver::poll`] when no event is ready.
const POLL_TIMEOUT_MS: u64 = 50;

/// Capacity of the per-connection event channel.
const EVENT_CHANNEL_CAPACITY: usize = 64;

// -------------------------------------------------------------------------
// TLS verifier — skips certificate validation, as required by §5
// -------------------------------------------------------------------------

/// A rustls verifier that accepts any server certificate.
///
/// QUIP has no CA to trust (§5); identity is established by the Key Claim
/// exchange, not by the TLS certificate.
#[derive(Debug)]
struct SkipVerifier;

impl ServerCertVerifier for SkipVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> core::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

// -------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------

/// Configuration for a server [`Endpoint`].
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// UDP address to bind.
    pub bind: SocketAddr,
    /// DER-encoded server certificate.
    pub cert_der: Vec<u8>,
    /// DER-encoded server private key (PKCS#8).
    pub key_der: Vec<u8>,
    /// The endpoint's self-signed identity claim (§5.1).
    ///
    /// Sent to every accepted peer as the `announce_key` verb during the
    /// §16 Key Claim exchange.
    pub key_claim: KeyClaim,
    /// Capabilities to advertise during the §4 handshake.
    ///
    /// The server's advertised set, not the client's, is what determines
    /// what verbs the connection can carry. Set this to whatever the
    /// server is prepared to serve.
    pub capabilities: Capabilities,
}

/// Configuration for a client [`Endpoint`].
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// UDP address to bind. Use port 0 to let the OS choose one.
    pub bind: SocketAddr,
    /// The endpoint's self-signed identity claim (§5.1).
    pub key_claim: KeyClaim,
    /// Capabilities to advertise during the §4 handshake.
    pub capabilities: Capabilities,
}

/// Which side of the connection we are.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// We called `connect()`; we open stream 0 and stream 4.
    Initiator,
    /// We were accepted via `accept()`; we accept stream 0 and stream 4.
    Responder,
}

/// A QUIP-over-QUIC endpoint.
///
/// Holds a [`QuipNetConfig`] that is used for every accepted or
/// initiated connection. The advertised capability set comes from this
/// config, so a server that wants to serve `merkle_range` must advertise
/// it here.
pub struct Endpoint {
    inner: QuinnEndpoint,
    /// The endpoint's identity, sent on every new connection.
    key_claim: KeyClaim,
    /// The transport-layer config used for every connection.
    config: QuipNetConfig,
}

impl Endpoint {
    /// Bind a server endpoint.
    pub fn server(config: ServerConfig) -> Result<Self> {
        let cert = CertificateDer::from(config.cert_der);
        let key = PrivateKeyDer::try_from(config.key_der)
            .map_err(|e| Error::Transport(format!("server key: {e}")))?;

        let mut rustls_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| Error::Transport(format!("server tls: {e}")))?;
        rustls_cfg.alpn_protocols = vec![ALPN_QUIP.to_vec()];

        let quic_cfg = QuicServerConfig::try_from(rustls_cfg)
            .map_err(|e| Error::Transport(format!("server quic tls: {e}")))?;
        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));

        let inner = QuinnEndpoint::server(server_cfg, config.bind)
            .map_err(|e| Error::Transport(format!("bind {}: {e}", config.bind)))?;

        let net_config = QuipNetConfig {
            capabilities: config.capabilities,
            ..QuipNetConfig::default()
        };

        Ok(Self {
            inner,
            key_claim: config.key_claim,
            config: net_config,
        })
    }

    /// Bind a client endpoint.
    pub fn client(config: ClientConfig) -> Result<Self> {
        let mut rustls_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerifier))
            .with_no_client_auth();
        rustls_cfg.alpn_protocols = vec![ALPN_QUIP.to_vec()];

        let quic_cfg = QuicClientConfig::try_from(rustls_cfg)
            .map_err(|e| Error::Transport(format!("client quic tls: {e}")))?;
        let client_cfg = quinn::ClientConfig::new(Arc::new(quic_cfg));

        let mut inner = QuinnEndpoint::client(config.bind)
            .map_err(|e| Error::Transport(format!("bind {}: {e}", config.bind)))?;
        inner.set_default_client_config(client_cfg);

        let net_config = QuipNetConfig {
            capabilities: config.capabilities,
            ..QuipNetConfig::default()
        };

        Ok(Self {
            inner,
            key_claim: config.key_claim,
            config: net_config,
        })
    }

    /// The endpoint's identity claim.
    pub fn key_claim(&self) -> &KeyClaim {
        &self.key_claim
    }

    /// The transport-layer config this endpoint uses for every
    /// connection.
    pub fn config(&self) -> &QuipNetConfig {
        &self.config
    }

    /// The local address this endpoint is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.inner
            .local_addr()
            .map_err(|e| Error::Transport(format!("local_addr: {e}")))
    }

    /// Wait for the next inbound connection.
    ///
    /// The returned driver is in [`DriverPhase::Connecting`]. Drive it
    /// with [`ConnectionDriver::poll`] until the handshake and Key Claim
    /// exchange complete.
    pub async fn accept(&self) -> Result<Option<ConnectionDriver>> {
        match self.inner.accept().await {
            None => Ok(None),
            Some(incoming) => {
                let conn = incoming
                    .await
                    .map_err(|e| Error::Transport(format!("accept: {e}")))?;
                Ok(Some(ConnectionDriver::from_connection(
                    conn,
                    self.config,
                    Role::Responder,
                    self.key_claim.clone(),
                )))
            }
        }
    }

    /// Connect to a remote server.
    ///
    /// Uses the endpoint's own [`QuipNetConfig`]; callers that want a
    /// different config construct a second endpoint.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<ConnectionDriver> {
        let connecting = self
            .inner
            .connect(addr, server_name)
            .map_err(|e| Error::Transport(format!("connect {addr}: {e}")))?;
        let conn = connecting
            .await
            .map_err(|e| Error::Transport(format!("connect {addr}: {e}")))?;
        Ok(ConnectionDriver::from_connection(
            conn,
            self.config,
            Role::Initiator,
            self.key_claim.clone(),
        ))
    }

    /// Initiate a graceful close of the endpoint.
    pub fn close(&self) {
        self.inner.close(0u32.into(), b"");
    }

    /// Wait until every connection on this endpoint has drained.
    pub async fn wait_idle(&self) {
        self.inner.wait_idle().await;
    }
}

// -------------------------------------------------------------------------
// Message + event types
// -------------------------------------------------------------------------

/// A parsed inbound QUIP message: tier + decoded CBOR.
#[derive(Debug)]
pub struct IncomingMessage {
    /// Tier the message arrived on.
    pub tier: Tier,
    /// Stream (T0/T1/T2) or `None` for a T3 datagram.
    pub stream: Option<u64>,
    /// Decoded CBOR payload.
    pub value: CborValue,
    /// Raw bytes as received (post-deframe for T0/T1/T2, verbatim for T3).
    pub raw: Vec<u8>,
}

impl IncomingMessage {
    /// Extract the verb string from this message.
    pub fn verb(&self) -> Result<&str> {
        crate::codec::verb_of(&self.value)
    }
}

/// Events emitted by [`ConnectionDriver`] for the hosting application.
#[derive(Debug)]
pub enum Event {
    /// A T0/T1/T2 frame was received on `stream`.
    Frame {
        /// Tier.
        tier: Tier,
        /// QUIC stream ID.
        stream: u64,
        /// Decoded message.
        msg: IncomingMessage,
    },
    /// A T3 datagram was received (no stream ID).
    Datagram {
        /// Decoded message.
        msg: IncomingMessage,
    },
    /// A new T2 stream was opened by the peer.
    BulkStreamOpened {
        /// QUIC stream ID.
        stream: u64,
    },
    /// The T0 control stream is open, the §4 handshake has been
    /// exchanged, and the §16 Key Claim exchange has completed.
    ControlConnected {
        /// QUIC stream ID (always 0).
        stream: u64,
    },
    /// A stream or the connection failed.
    Error {
        /// Tier the error occurred on, if known.
        tier: Option<Tier>,
        /// Stream ID, if known.
        stream: Option<u64>,
        /// The error.
        error: Error,
    },
}

// -------------------------------------------------------------------------
// Driver phase
// -------------------------------------------------------------------------

/// Lifecycle phase of a [`ConnectionDriver`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DriverPhase {
    /// T0 stream not yet open; handshake not yet exchanged.
    Connecting,
    /// §4 handshake done, Key Claims not yet exchanged.
    ///
    /// This phase is transient: `poll_handshake` moves through it
    /// inline, so callers of `poll` never observe it as a stable state.
    /// It exists so the driver's internal state machine has a name for
    /// the window between the two exchanges.
    KeyClaimExchanging,
    /// Handshake and Key Claim exchange both complete; all tiers live.
    Established,
    /// Connection closed.
    Closed,
}

// -------------------------------------------------------------------------
// Connection driver
// -------------------------------------------------------------------------

/// State machine driving a single QUIC connection through the QUIP
/// lifecycle.
pub struct ConnectionDriver {
    /// Underlying QUIC connection.
    conn: quinn::Connection,
    /// Transport-layer state machine (framing, tiers, capabilities).
    transport: QuipConnection,
    /// Which side of the connection we are.
    role: Role,
    /// Current lifecycle phase.
    phase: DriverPhase,

    /// Our self-signed identity claim, sent during the Key Claim
    /// exchange.
    local_key_claim: KeyClaim,
    /// The peer's Key Claim, received during the exchange.
    ///
    /// **Not verified.** Callers MUST verify the signature against the
    /// `NodeId` in the claim before treating the peer's identity as
    /// established.
    peer_key_claim: Option<KeyClaim>,

    /// Receive-side rate limiter, keyed by the peer's NodeId once the
    /// Key Claim exchange completes.
    ///
    /// Before then, `peer_key_claim` is `None` and the driver does not
    /// rate-limit; the handshake itself is short and QUIC-bounded.
    ///
    /// Enforcement is per-connection: the limiter holds buckets for the
    /// one peer this driver talks to. Sharing a budget across many
    /// connections would require hoisting the limiter above the driver.
    rate_limiter: RateLimiter,
    /// T1 SYNC stream state machine (§11). Tracks whether T1 is
    /// currently serving a request.
    ///
    /// Fed inbound T1 request frames via
    /// [`crate::sync_stream::SyncStream::classify_verb`],
    /// and returned to `Idle` by the next successful T1 write while busy.
    /// See the module docs for the heuristic.
    sync_stream: SyncStream,

    /// Per-peer exponential backoff tracker (§19.4).
    ///
    /// Records consecutive protocol errors on this connection so the
    /// caller can throttle a repeat offender. The driver records only;
    /// the retry policy belongs to whichever layer dials the connection.
    backoff: BackoffTracker<NodeId>,

    // ---- T0 ----
    /// T0 send half, held for the connection's lifetime.
    control_send: Option<quinn::SendStream>,
    /// T0 receive half, moved into the read task after the exchange.
    control_recv: Option<quinn::RecvStream>,

    // ---- T1 ----
    /// T1 send half, held for the connection's lifetime.
    sync_send: Option<quinn::SendStream>,
    /// Scratch slot for the T1 receive half between
    /// `open_or_accept_t1` and `spawn_readers`. Private to the driver.
    t1_recv_scratch: Option<quinn::RecvStream>,

    // ---- T2 ----
    /// Outbound T2 streams, keyed by the resource being transferred.
    ///
    /// Both halves are held: the send half for writing, and the receive
    /// half to keep the stream alive. Dropping the receive half of a
    /// bi-directional QUIC stream sends STOP_SENDING to the peer, which
    /// tears down the peer's read side and silently drops any frames
    /// that were still in flight.
    bulk_sends: BTreeMap<Vec<u8>, (quinn::SendStream, quinn::RecvStream)>,

    // ---- read tasks ----
    /// Receiver for events produced by the read tasks.
    event_rx: Option<mpsc::Receiver<Event>>,
    /// Handles for the tasks spawned by `spawn_readers`. Aborted on drop.
    read_tasks: Vec<JoinHandle<()>>,

    // ---- progress flags ----
    /// True once our handshake has been written to T0.
    handshake_sent: bool,
    /// True once the remote handshake has been read and negotiated.
    handshake_done: bool,
    /// True once we have written our `announce_key` on T0.
    key_claim_sent: bool,
    /// True once the peer's `announce_key` has been read and stored.
    key_claim_received: bool,
}

impl core::fmt::Debug for ConnectionDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConnectionDriver")
            .field("remote", &self.conn.remote_address())
            .field("role", &self.role)
            .field("phase", &self.phase)
            .field("handshake_done", &self.handshake_done)
            .field("key_claim_received", &self.key_claim_received)
            .finish()
    }
}

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        for task in &self.read_tasks {
            task.abort();
        }
    }
}

impl ConnectionDriver {
    /// Build a driver from a completed `quinn::Connection`.
    ///
    /// `local_key_claim` is the identity this endpoint will announce on
    /// the connection; typically it is the same claim the enclosing
    /// [`Endpoint`] holds.
    pub fn from_connection(
        conn: quinn::Connection,
        config: QuipNetConfig,
        role: Role,
        local_key_claim: KeyClaim,
    ) -> Self {
        let transport = match role {
            Role::Initiator => QuipConnection::new_initiator(config),
            Role::Responder => QuipConnection::new_responder(config),
        };
        Self {
            conn,
            transport,
            role,
            phase: DriverPhase::Connecting,
            local_key_claim,
            peer_key_claim: None,
            rate_limiter: RateLimiter::new(),
            sync_stream: SyncStream::new(),
            backoff: BackoffTracker::new(),
            control_send: None,
            control_recv: None,
            sync_send: None,
            t1_recv_scratch: None,
            bulk_sends: BTreeMap::new(),
            event_rx: None,
            read_tasks: Vec::new(),
            handshake_sent: false,
            handshake_done: false,
            key_claim_sent: false,
            key_claim_received: false,
        }
    }

    /// Current lifecycle phase.
    pub fn phase(&self) -> DriverPhase {
        self.phase
    }

    /// Which side of the connection we are.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The negotiated capabilities (after handshake).
    pub fn agreed(&self) -> Option<crate::handshake::Capabilities> {
        self.transport.agreed()
    }

    /// The peer's Key Claim, once the §16 exchange has completed.
    ///
    /// **The signature is not verified by the driver.** Callers MUST
    /// verify `claim.signature` against `claim.node_id` — and check the
    /// resulting identity against their TOFU / rotation policy — before
    /// trusting the peer.
    pub fn peer_key_claim(&self) -> Option<&KeyClaim> {
        self.peer_key_claim.as_ref()
    }

    /// The peer's NodeId, once the §16 Key Claim exchange has completed.
    ///
    /// Returns `None` before the exchange completes. The returned NodeId
    /// is the peer's claimed identity — the driver does not verify the
    /// signature that vouches for it (see [`Self::peer_key_claim`]).
    pub fn peer_node_id(&self) -> Option<NodeId> {
        self.peer_key_claim.as_ref().map(|c| c.node_id)
    }

    /// Our own Key Claim.
    pub fn local_key_claim(&self) -> &KeyClaim {
        &self.local_key_claim
    }

    /// The receive-side rate limiter.
    ///
    /// Useful for inspection: a caller can check whether the peer is
    /// approaching a limit before deciding to close the connection.
    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }

    /// Mutable access to the receive-side rate limiter.
    ///
    /// Callers wanting to adjust the limiter's configuration should use
    /// [`Self::set_rate_config`], which replaces the limiter wholesale
    /// rather than mutating its config in place.
    pub fn rate_limiter_mut(&mut self) -> &mut RateLimiter {
        &mut self.rate_limiter
    }

    /// Replace the rate limiter with one configured by `config`.
    ///
    /// **Discards accumulated state.** Any buckets the previous limiter
    /// held are dropped. This is safe when called before the first poll
    /// (which is the intended use: configure, then drive); a caller that
    /// swaps the limiter mid-connection resets that peer's budget.
    pub fn set_rate_config(&mut self, config: RateLimiterConfig) {
        self.rate_limiter = RateLimiter::with_config(config);
    }

    /// The T1 SYNC stream state machine (§11).
    ///
    /// Callers that want to gate their own T1 writes on the state can
    /// consult this; the driver also drives it automatically (see the
    /// module docs for the heuristic).
    pub fn sync_stream(&self) -> &SyncStream {
        &self.sync_stream
    }

    /// The per-peer backoff tracker (§19.4).
    ///
    /// Consult before dialing or retrying against the current peer.
    /// `BackoffTracker::can_attempt(peer, now)` answers "is this peer
    /// worth retrying right now?" for a caller that keys on the peer
    /// NodeId.
    pub fn backoff(&self) -> &BackoffTracker<NodeId> {
        &self.backoff
    }

    /// Local IP address of this connection, if the runtime has resolved
    /// it yet.
    pub fn local_ip(&self) -> Option<std::net::IpAddr> {
        self.conn.local_ip()
    }

    /// Remote UDP address of this connection.
    pub fn remote_addr(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// Reason the connection was closed, or `None` if still open.
    pub fn close_reason(&self) -> Option<quinn::ConnectionError> {
        self.conn.close_reason()
    }

    /// Returns `true` once the T0 handshake and the Key Claim exchange
    /// have both completed.
    pub fn is_handshaked(&self) -> bool {
        self.handshake_done && self.key_claim_received
    }

    // ---------------------------------------------------------------------
    // Poll — handshake, Key Claim exchange, event drain
    // ---------------------------------------------------------------------

    /// Drive one tick of work on this connection.
    ///
    /// On the first successful call, opens the T0 control stream,
    /// exchanges the §4 handshake, exchanges the §16 Key Claims, opens
    /// T1, spawns the read tasks, and returns
    /// `[Event::ControlConnected]`. The driver ends in
    /// [`DriverPhase::Established`].
    ///
    /// On subsequent calls, waits up to `POLL_TIMEOUT_MS` for an event
    /// and returns whatever arrived, draining any further ready events.
    /// An idle connection returns an empty vector, not an error.
    ///
    /// Once the peer's NodeId is known, each inbound `Frame` or
    /// `Datagram` is checked against the rate limiter. Frames over
    /// budget are replaced with `Event::Error { error: RateLimit }`.
    /// T2 (bulk) frames are exempt.
    pub async fn poll(&mut self, now: Timestamp) -> Result<Vec<Event>> {
        if self.phase == DriverPhase::Closed {
            return Ok(Vec::new());
        }
        if let Some(err) = self.conn.close_reason() {
            self.phase = DriverPhase::Closed;
            return Err(Error::Transport(format!("connection closed: {err}")));
        }

        // ---- Handshake + Key Claim path ----
        if self.phase != DriverPhase::Established {
            let events = self.poll_handshake(now).await?;
            let events = self.apply_rate_limits(events, now);
            self.note_events(&events, now);
            return Ok(events);
        }

        // ---- Established path: drain the event channel ----
        let rx = match self.event_rx.as_mut() {
            Some(rx) => rx,
            None => return Ok(Vec::new()),
        };

        let mut events = Vec::new();
        match tokio::time::timeout(Duration::from_millis(POLL_TIMEOUT_MS), rx.recv()).await {
            Ok(Some(event)) => events.push(event),
            Ok(None) => {
                self.phase = DriverPhase::Closed;
                return Ok(events);
            }
            Err(_) => return Ok(events),
        }
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        let events = self.apply_rate_limits(events, now);
        self.note_events(&events, now);
        Ok(events)
    }

    /// Apply rate limits to `events`.
    ///
    /// For each `Frame` or `Datagram`, look up the operation kind from
    /// the verb and consult the limiter. Exceeding the limit replaces
    /// the event with `Event::Error { error: RateLimit }`.
    ///
    /// No-op before the peer's NodeId is known.
    fn apply_rate_limits(&mut self, events: Vec<Event>, now: Timestamp) -> Vec<Event> {
        // Copy out the peer's NodeId so the mutable borrow of the
        // limiter below is not entangled with an immutable borrow of
        // `peer_key_claim`.
        let peer = match self.peer_key_claim.as_ref() {
            Some(c) => c.node_id,
            None => return events,
        };

        // Cheap sweep: drop buckets that have refilled to capacity.
        self.rate_limiter.sweep(now);

        let mut out = Vec::with_capacity(events.len());
        for event in events {
            let replacement = match &event {
                Event::Frame { tier, stream, msg } => {
                    // Bulk (T2) traffic is bounded by stream-level flow
                    // control, not by ops/min.
                    if matches!(tier, Tier::Bulk) {
                        None
                    } else {
                        let kind = operation_kind_for(msg);
                        if self.rate_limiter.check(peer, kind, now).is_ok() {
                            None
                        } else {
                            Some(Event::Error {
                                tier: Some(*tier),
                                stream: Some(*stream),
                                error: Error::RateLimit,
                            })
                        }
                    }
                }
                Event::Datagram { msg } => {
                    let kind = operation_kind_for(msg);
                    if self.rate_limiter.check(peer, kind, now).is_ok() {
                        None
                    } else {
                        Some(Event::Error {
                            tier: Some(Tier::Event),
                            stream: None,
                            error: Error::RateLimit,
                        })
                    }
                }
                _ => None,
            };
            out.push(replacement.unwrap_or(event));
        }
        out
    }

    /// Feed the T1 SYNC stream state machine and the per-peer backoff
    /// tracker from `events`.
    ///
    /// Called from [`Self::poll`] after rate limiting, so the state
    /// machine sees only the events the application will see.
    ///
    /// A protocol error on T1 puts the state machine into its terminal
    /// `Error` state; errors on other tiers bump the backoff tracker
    /// but leave T1 alone.
    fn note_events(&mut self, events: &[Event], now: Timestamp) {
        let peer = self.peer_key_claim.as_ref().map(|c| c.node_id);

        for event in events {
            match event {
                Event::Frame {
                    tier: Tier::Sync,
                    msg,
                    ..
                } => {
                    if let Ok(verb) = msg.verb() {
                        if let Some(ev) = SyncStream::classify_verb(verb) {
                            // A rejected transition (request while busy)
                            // is not itself an error event; the state
                            // machine ignores it. The application can
                            // observe the state via `sync_stream()`.
                            let _ = self.sync_stream.on_event(ev);
                        }
                    }
                }
                Event::Error {
                    tier: Some(Tier::Sync),
                    ..
                } => {
                    if let Some(peer) = peer {
                        self.backoff.record_failure(peer, now);
                    }
                    let _ = self.sync_stream.on_event(SyncEvent::ProtocolError(
                        alloc::string::String::from("T1 stream error"),
                    ));
                }
                Event::Error { .. } => {
                    if let Some(peer) = peer {
                        self.backoff.record_failure(peer, now);
                    }
                }
                _ => {}
            }
        }
    }

    /// Drive the §4 handshake and §16 Key Claim exchange to completion,
    /// then spawn the read tasks.
    async fn poll_handshake(&mut self, now: Timestamp) -> Result<Vec<Event>> {
        // ---- Phase 1: open (initiator) or accept (responder) T0. ----
        if self.control_send.is_none() {
            let (send, recv) = match self.role {
                Role::Initiator => self
                    .conn
                    .open_bi()
                    .await
                    .map_err(|e| Error::Transport(format!("open T0: {e}")))?,
                Role::Responder => self
                    .conn
                    .accept_bi()
                    .await
                    .map_err(|e| Error::Transport(format!("accept T0: {e}")))?,
            };
            self.control_send = Some(send);
            self.control_recv = Some(recv);
        }

        // ---- Phase 2: write our §4 handshake. ----
        if !self.handshake_sent {
            let bytes = self.transport.handshake_bytes()?;
            let send = self
                .control_send
                .as_mut()
                .expect("control_send set in phase 1");
            write_all_cancel_safe(send, &bytes).await?;
            self.handshake_sent = true;
        }

        // ---- Phase 3: read the remote §4 handshake. ----
        if !self.handshake_done {
            let recv = self
                .control_recv
                .as_mut()
                .expect("control_recv set in phase 1");
            let remote_bytes = read_handshake(recv).await?;
            self.transport.on_handshake(&remote_bytes, now)?;
            self.handshake_done = true;
            self.phase = DriverPhase::KeyClaimExchanging;
        }

        // ---- Phase 4: write our Key Claim. ----
        if !self.key_claim_sent {
            let announce = Message::AnnounceKey(self.local_key_claim.clone());
            let bytes = announce.to_bytes()?;
            let framed = frame::encode_message(&bytes)?;
            let send = self
                .control_send
                .as_mut()
                .expect("control_send set in phase 1");
            write_all_cancel_safe(send, &framed).await?;
            self.key_claim_sent = true;
        }

        // ---- Phase 5: read the peer's Key Claim. ----
        if !self.key_claim_received {
            let recv = self
                .control_recv
                .as_mut()
                .expect("control_recv set in phase 1");
            let payload = read_one_frame(recv).await?;
            let claimed = message::dispatch(&payload, Tier::Ctrl)?;
            match claimed {
                Message::AnnounceKey(claim) => self.peer_key_claim = Some(claim),
                other => {
                    return Err(Error::Transport(format!(
                        "expected announce_key during Key Claim exchange, got `{}`",
                        other.verb()
                    )));
                }
            }
            self.key_claim_received = true;
        }

        // ---- Phase 6: open/accept T1 and spawn the read tasks. ----
        self.open_or_accept_t1().await?;
        self.spawn_readers()?;
        self.phase = DriverPhase::Established;

        Ok(vec![Event::ControlConnected { stream: 0 }])
    }

    /// Open (initiator) or accept (responder) the T1 stream.
    ///
    /// The initiator writes a no-op flow-control frame on T1 immediately
    /// after opening it. QUIC creates a stream on the peer only when the
    /// first `STREAM` frame arrives, so without this write the
    /// responder's `accept_bi` would block until the first application
    /// message — which may never come. The frame is consumed silently by
    /// `route_message` and produces no application event.
    async fn open_or_accept_t1(&mut self) -> Result<()> {
        let (mut send, recv) = match self.role {
            Role::Initiator => self
                .conn
                .open_bi()
                .await
                .map_err(|e| Error::Transport(format!("open T1: {e}")))?,
            Role::Responder => self
                .conn
                .accept_bi()
                .await
                .map_err(|e| Error::Transport(format!("accept T1: {e}")))?,
        };

        if matches!(self.role, Role::Initiator) {
            let hello = FlowFrame::Window { bytes: u64::MAX };
            let hello_bytes = hello.to_bytes()?;
            let framed = frame::encode_message(&hello_bytes)?;
            write_all_cancel_safe(&mut send, &framed).await?;
        }

        self.sync_send = Some(send);
        self.t1_recv_scratch = Some(recv);
        Ok(())
    }

    /// Spawn the T0/T1/T2-accept/T3 read tasks.
    fn spawn_readers(&mut self) -> Result<()> {
        let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        self.event_rx = Some(rx);

        if let Some(recv) = self.control_recv.take() {
            let tx = tx.clone();
            self.read_tasks
                .push(tokio::spawn(read_loop(recv, Tier::Ctrl, CTRL_STREAM_ID, tx)));
        }

        if let Some(recv) = self.t1_recv_scratch.take() {
            let tx = tx.clone();
            self.read_tasks
                .push(tokio::spawn(read_loop(recv, Tier::Sync, SYNC_STREAM_ID, tx)));
        }

        let conn_t2 = self.conn.clone();
        let tx_t2 = tx.clone();
        self.read_tasks
            .push(tokio::spawn(accept_bulk_loop(
                conn_t2,
                tx_t2,
                T2_MAX_STREAMS,
            )));

        let conn_t3 = self.conn.clone();
        let tx_t3 = tx;
        self.read_tasks
            .push(tokio::spawn(datagram_loop(conn_t3, tx_t3)));

        Ok(())
    }

    // ---------------------------------------------------------------------
    // Outbound
    // ---------------------------------------------------------------------

    /// Send a QUIP message.
    ///
    /// Routes by [`Message::required_tier`]. Checks the negotiated
    /// capability set before sending; a verb whose required capability
    /// was not advertised is rejected locally with
    /// [`Error::CapabilityViolation`] (§4).
    ///
    /// Send-side rate limiting is not enforced here: the limits in
    /// §19.4 bound what a peer may send *to us*, not what we choose to
    /// send. The application decides whether its own outbound traffic
    /// is within its own policy.
    pub async fn send(&mut self, msg: &Message, _now: Timestamp) -> Result<()> {
        let negotiated = self
            .transport
            .agreed()
            .ok_or(Error::Handshake("send before handshake"))?;
        msg.check_capability(negotiated)?;

        let tier = msg.required_tier();
        let bytes = msg.to_bytes()?;

        match tier {
            Tier::Ctrl => {
                let framed = frame::encode_message(&bytes)?;
                let send = self
                    .control_send
                    .as_mut()
                    .ok_or_else(|| Error::Transport("T0 not open".into()))?;
                write_all_cancel_safe(send, &framed).await?;
            }
            Tier::Sync => {
                let framed = frame::encode_message(&bytes)?;
                {
                    let send = self
                        .sync_send
                        .as_mut()
                        .ok_or_else(|| Error::Transport("T1 not open".into()))?;
                    write_all_cancel_safe(send, &framed).await?;
                }
                // If the state machine was waiting on a response, this
                // write is it. The heuristic treats any successful T1
                // write while busy as the response; a caller that needs
                // finer control can drive `sync_stream()` directly.
                if self.sync_stream.state().is_busy() {
                    let _ = self.sync_stream.on_event(SyncEvent::ResponseSent);
                }
            }
            Tier::Bulk => self.send_bulk(msg, &bytes).await?,
            Tier::Event => {
                if bytes.len() > MAX_DGRAM_BYTES {
                    return Err(Error::TooLarge {
                        size: bytes.len(),
                        max: MAX_DGRAM_BYTES,
                    });
                }
                self.conn
                    .send_datagram(bytes.into())
                    .map_err(|e| Error::Transport(format!("send T3: {e}")))?;
            }
        }
        Ok(())
    }

    /// Route a T2 verb to the correct per-resource stream.
    async fn send_bulk(&mut self, msg: &Message, bytes: &[u8]) -> Result<()> {
        let framed = frame::encode_message(bytes)?;
        match msg {
            Message::SendStart(s) => {
                let (mut send, recv) = self
                    .conn
                    .open_bi()
                    .await
                    .map_err(|e| Error::Transport(format!("open T2: {e}")))?;
                write_all_cancel_safe(&mut send, &framed).await?;
                self.bulk_sends.insert(s.resource_id.clone(), (send, recv));
            }
            Message::SendChunk(c) => {
                let (send, _) = self
                    .bulk_sends
                    .get_mut(&c.resource_id)
                    .ok_or_else(|| Error::Transport("no open T2 stream".into()))?;
                write_all_cancel_safe(send, &framed).await?;
            }
            Message::SendComplete(c) => {
                let (mut send, _recv) = self
                    .bulk_sends
                    .remove(&c.resource_id)
                    .ok_or_else(|| Error::Transport("no open T2 stream".into()))?;
                write_all_cancel_safe(&mut send, &framed).await?;
                send.finish()
                    .map_err(|e| Error::Transport(format!("finish T2: {e}")))?;
                // `_recv` drops here, after the send half has finished.
                // This is fine: the transfer is already complete, and
                // the peer has seen the FIN.
            }
            _ => {
                return Err(Error::Transport(
                    "non-bulk verb routed to T2 (programmer error)".into(),
                ))
            }
        }
        Ok(())
    }

    /// Access the underlying connection for future work.
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &quinn::Connection {
        &self.conn
    }
}

// -------------------------------------------------------------------------
// Rate limiting helpers
// -------------------------------------------------------------------------

/// Classify an inbound message into a rate-limit operation kind.
///
/// The mapping mirrors the §19.4 categories. Verbs that are not listed
/// fall under [`OperationKind::General`].
///
/// `relay_discovery` and `relay_response` are DHT-plane messages
/// (§12.2) and do not normally appear on a peer connection, but the
/// classification is provided for completeness.
fn operation_kind_for(msg: &IncomingMessage) -> OperationKind {
    match msg.verb().unwrap_or("") {
        "pin_announce" => OperationKind::PinAnnounce,
        "spillover" | "spillover_response" => OperationKind::Spillover,
        "relay_discovery" | "relay_response" => OperationKind::Relay,
        "register_tcid" | "delegation" | "quarantine" | "unquarantine"
        | "derivative_link" => OperationKind::Governance,
        _ => OperationKind::General,
    }
}

// -------------------------------------------------------------------------
// Read tasks
// -------------------------------------------------------------------------

/// Read framed messages from `recv`, dispatch each, and forward events
/// on `tx` until the stream closes or a protocol error is encountered.
async fn read_loop(
    mut recv: quinn::RecvStream,
    tier: Tier,
    stream: u64,
    tx: mpsc::Sender<Event>,
) {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];

    loop {
        let n = match recv.read(&mut tmp).await {
            Ok(Some(n)) => n,
            Ok(None) => return,
            Err(e) => {
                let _ = tx
                    .send(Event::Error {
                        tier: Some(tier),
                        stream: Some(stream),
                        error: Error::Transport(format!(
                            "read T{} stream {stream}: {e}",
                            tier as u8
                        )),
                    })
                    .await;
                return;
            }
        };
        buf.extend_from_slice(&tmp[..n]);

        loop {
            match frame::try_deframe(&buf) {
                Ok(Some((msg, consumed))) => {
                    if let Some(event) = route_message(msg, tier, stream) {
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                    buf.drain(..consumed);
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = tx
                        .send(Event::Error {
                            tier: Some(tier),
                            stream: Some(stream),
                            error: e,
                        })
                        .await;
                    return;
                }
            }
        }
    }
}

/// Classify an incoming message and produce the corresponding event.
fn route_message(bytes: &[u8], tier: Tier, stream: u64) -> Option<Event> {
    if matches!(tier, Tier::Sync | Tier::Bulk) {
        if let Some(flow_result) = dispatch_flow(bytes) {
            return match flow_result {
                Ok(_frame) => None,
                Err(e) => Some(Event::Error {
                    tier: Some(tier),
                    stream: Some(stream),
                    error: e,
                }),
            };
        }
    }

    if let Err(e) = message::dispatch(bytes, tier) {
        return Some(Event::Error {
            tier: Some(tier),
            stream: Some(stream),
            error: e,
        });
    }

    match quip_core::cbor::decode(bytes) {
        Ok(value) => Some(Event::Frame {
            tier,
            stream,
            msg: IncomingMessage {
                tier,
                stream: Some(stream),
                value,
                raw: bytes.to_vec(),
            },
        }),
        Err(e) => Some(Event::Error {
            tier: Some(tier),
            stream: Some(stream),
            error: e.into(),
        }),
    }
}

/// Accept T2 streams from the peer and spawn a read task for each.
///
/// Concurrency is bounded by a semaphore of `max_streams` permits. A
/// permit is acquired before `accept_bi` and released when the read task
/// for that stream ends, so a peer that opens more concurrent bulk
/// streams than the cap gets QUIC-level backpressure rather than the
/// driver queueing unboundedly.
async fn accept_bulk_loop(
    conn: quinn::Connection,
    tx: mpsc::Sender<Event>,
    max_streams: usize,
) {
    let permits = Arc::new(Semaphore::new(max_streams.max(1)));

    loop {
        let permit = match permits.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };

        match conn.accept_bi().await {
            Ok((_send, recv)) => {
                let stream_id = wire_stream_id(recv.id());
                if tx
                    .send(Event::BulkStreamOpened { stream: stream_id })
                    .await
                    .is_err()
                {
                    return;
                }
                let tx = tx.clone();
                tokio::spawn(async move {
                    read_loop(recv, Tier::Bulk, stream_id, tx).await;
                    // Released when the read task exits, freeing a slot
                    // for the next inbound bulk stream.
                    drop(permit);
                });
            }
            Err(_) => return,
        }
    }
}

/// Read T3 datagrams and forward them as events.
async fn datagram_loop(conn: quinn::Connection, tx: mpsc::Sender<Event>) {
    loop {
        match conn.read_datagram().await {
            Ok(bytes) => {
                let value = match quip_core::cbor::decode(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        if tx
                            .send(Event::Error {
                                tier: Some(Tier::Event),
                                stream: None,
                                error: e.into(),
                            })
                            .await
                            .is_err()
                        {
                            return;
                        }
                        continue;
                    }
                };
                let incoming = IncomingMessage {
                    tier: Tier::Event,
                    stream: None,
                    value,
                    raw: bytes.to_vec(),
                };
                if tx.send(Event::Datagram { msg: incoming }).await.is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// Reconstruct the QUIC wire stream ID from a `quinn::StreamId`.
///
/// QUIC encodes the initiator and directionality in the low two bits:
/// `00` = client bidi, `01` = server bidi, `10` = client uni,
/// `11` = server uni. Bits 2+ are the index.
fn wire_stream_id(id: quinn::StreamId) -> u64 {
    let initiator = match id.initiator() {
        quinn::Side::Client => 0u64,
        quinn::Side::Server => 1u64,
    };
    let dir = match id.dir() {
        quinn::Dir::Bi => 0u64,
        quinn::Dir::Uni => 2u64,
    };
    (id.index() << 2) | dir | initiator
}

/// Write every byte of `bytes` to `send`, using cancel-safe `write()`
/// calls in a loop.
async fn write_all_cancel_safe(send: &mut quinn::SendStream, bytes: &[u8]) -> Result<()> {
    let mut written = 0usize;
    while written < bytes.len() {
        let n = send
            .write(&bytes[written..])
            .await
            .map_err(|e| Error::Transport(format!("write stream: {e}")))?;
        if n == 0 {
            return Err(Error::Transport("send stream accepted zero bytes".into()));
        }
        written += n;
    }
    Ok(())
}

/// Read exactly one §4 handshake from `recv`.
///
/// The handshake is raw CBOR with no length prefix; read byte-by-byte
/// until the CBOR parses.
async fn read_handshake(recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let mut byte = [0u8; 1];
        recv.read_exact(&mut byte)
            .await
            .map_err(|e| Error::Transport(format!("read handshake: {e}")))?;
        buf.push(byte[0]);

        if crate::handshake::Handshake::from_bytes(&buf).is_ok() {
            return Ok(buf);
        }
        if buf.len() > MAX_HANDSHAKE_BYTES {
            return Err(Error::Handshake("handshake exceeds maximum size"));
        }
    }
}

/// Read one framed QUIP message (varint length prefix + CBOR) from
/// `recv`, returning the CBOR payload without the prefix.
///
/// Used during the Key Claim exchange, before the read tasks exist.
async fn read_one_frame(recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    // Read the varint length prefix.
    let mut prefix: Vec<u8> = Vec::with_capacity(8);
    loop {
        let mut byte = [0u8; 1];
        recv.read_exact(&mut byte)
            .await
            .map_err(|e| Error::Transport(format!("read frame prefix: {e}")))?;
        prefix.push(byte[0]);
        if prefix.len() >= frame::varint_len(prefix[0]) {
            break;
        }
    }
    let (len, _) = frame::decode_varint(&prefix)?;
    let len = len as usize;
    if len > crate::constants::MAX_MESSAGE_SIZE {
        return Err(Error::TooLarge {
            size: len,
            max: crate::constants::MAX_MESSAGE_SIZE,
        });
    }

    let mut payload = alloc::vec![0u8; len];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| Error::Transport(format!("read frame payload: {e}")))?;
    Ok(payload)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EmitEvent;
    use crate::rate::BucketConfig;
    use crate::sync::GetRequest;
    use quip_core::dvv::Dvv;
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    fn make_cert() -> (Vec<u8>, Vec<u8>) {
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("rcgen self-signed");
        (cert.der().to_vec(), key_pair.serialize_der())
    }

    fn localhost_zero() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn nid(b: u8) -> quip_core::dvv::NodeId {
        [b; 32]
    }

    /// A deterministic Key Claim for tests. The signature is zero: the
    /// driver does not verify it, so a zero signature is fine and keeps
    /// the tests independent of the `crypto` feature.
    fn fake_key_claim(seed: u8) -> KeyClaim {
        KeyClaim {
            node_id: [seed; 32],
            timestamp: now(),
            dht_id: [seed; 32],
            signature: [0u8; 64],
        }
    }

    /// Build a server config with the given capability set.
    fn server_config(seed: u8, caps: Capabilities) -> ServerConfig {
        let (cert_der, key_der) = make_cert();
        ServerConfig {
            bind: localhost_zero(),
            cert_der,
            key_der,
            key_claim: fake_key_claim(seed),
            capabilities: caps,
        }
    }

    /// Build a client config with the given capability set.
    fn client_config(seed: u8, caps: Capabilities) -> ClientConfig {
        ClientConfig {
            bind: localhost_zero(),
            key_claim: fake_key_claim(seed),
            capabilities: caps,
        }
    }

    fn server_endpoint(seed: u8) -> (Endpoint, SocketAddr) {
        let server = Endpoint::server(server_config(seed, Capabilities::baseline()))
            .expect("server bind");
        let addr = server.local_addr().expect("server local addr");
        (server, addr)
    }

    fn client_endpoint(seed: u8) -> Endpoint {
        Endpoint::client(client_config(seed, Capabilities::baseline()))
            .expect("client bind")
    }

    /// Drive both sides through the handshake and Key Claim exchange
    /// concurrently and return both drivers in the `Established` phase.
    ///
    /// Both sides advertise `Capabilities::baseline()`.
    async fn handshake_pair(
        server_seed: u8,
        client_seed: u8,
    ) -> (ConnectionDriver, ConnectionDriver) {
        handshake_pair_with(server_seed, client_seed, Capabilities::baseline()).await
    }

    /// Like `handshake_pair`, but both sides advertise `caps`.
    ///
    /// The capability set is a per-endpoint configuration: the server
    /// advertises it because it is what the server is prepared to
    /// serve, and the client advertises it because it is what the
    /// client is prepared to use. Both ends must agree for the
    /// capabilities to survive negotiation.
    async fn handshake_pair_with(
        server_seed: u8,
        client_seed: u8,
        caps: Capabilities,
    ) -> (ConnectionDriver, ConnectionDriver) {
        let server =
            Endpoint::server(server_config(server_seed, caps)).expect("server bind");
        let server_addr = server.local_addr().expect("server local addr");

        let server_fut = async move {
            let mut driver = server
                .accept()
                .await
                .expect("accept")
                .expect("endpoint open");
            driver.poll(now()).await.expect("server handshake");
            driver
        };

        let client_fut = async {
            let client = Endpoint::client(client_config(client_seed, caps))
                .expect("client bind");
            let mut driver = client
                .connect(server_addr, "localhost")
                .await
                .expect("client connect");
            driver.poll(now()).await.expect("client handshake");
            driver
        };

        tokio::join!(server_fut, client_fut)
    }

    /// Poll `driver` until it returns at least one event, or time out.
    async fn poll_until_event(
        driver: &mut ConnectionDriver,
        timeout_ms: u64,
    ) -> Result<Vec<Event>> {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let events = driver.poll(now()).await?;
            if !events.is_empty() {
                return Ok(events);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(Vec::new());
            }
        }
    }

    // ---- M5.2 behavior, preserved ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handshake_exchange_negotiates_capabilities() {
        let (server, client) = handshake_pair(1, 2).await;

        assert_eq!(client.phase(), DriverPhase::Established);
        assert_eq!(server.phase(), DriverPhase::Established);
        assert!(client.is_handshaked());
        assert!(server.is_handshaked());

        let client_agreed = client.agreed().expect("client agreed");
        let server_agreed = server.agreed().expect("server agreed");
        assert_eq!(client_agreed, server_agreed);
        assert!(client_agreed.has_baseline());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn poll_after_handshake_returns_no_events() {
        let (mut server, mut client) = handshake_pair(1, 2).await;

        let events = client.poll(now()).await.unwrap();
        assert!(events.is_empty());

        let events = server.poll(now()).await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn role_is_visible_on_the_driver() {
        let (server, server_addr) = server_endpoint(1);

        let server_handle = tokio::spawn(async move {
            let driver = server.accept().await.unwrap().unwrap();
            driver.role()
        });

        let client = client_endpoint(2);
        let client_driver = client
            .connect(server_addr, "localhost")
            .await
            .unwrap();

        assert_eq!(client_driver.role(), Role::Initiator);
        assert_eq!(server_handle.await.unwrap(), Role::Responder);
    }

    #[tokio::test]
    async fn closed_endpoint_yields_none_from_accept() {
        let (server, _) = server_endpoint(1);
        server.close();
        let result = server.accept().await.expect("accept on closed endpoint");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn connecting_to_unbound_address_fails() {
        let client = client_endpoint(1);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            client.connect("127.0.0.1:1".parse().unwrap(), "localhost"),
        )
        .await;

        // Either the connect failed (expected) or it timed out (also a
        // failure to connect). Both satisfy the assertion.
        match result {
            Ok(Ok(_)) => panic!("connect to a dead port should not succeed"),
            Ok(Err(e)) => assert!(matches!(e, Error::Transport(_))),
            Err(_) => {} // timed out
        }
    }

    // ---- M5.3 behavior, preserved ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_receive_on_t0() {
        let (mut server, mut client) = handshake_pair(1, 2).await;

        let msg = Message::Error(message::ErrorMessage {
            code: quip_core::ErrorCode::Violation,
            message_id: 7,
            text: "test".into(),
        });
        client.send(&msg, now()).await.expect("send error");

        let events = poll_until_event(&mut server, 500).await.unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Frame { tier, stream, msg } => {
                assert_eq!(*tier, Tier::Ctrl);
                assert_eq!(*stream, 0);
                assert_eq!(msg.verb().unwrap(), "error");
            }
            other => panic!("expected Frame on T0, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_receive_on_t1() {
        let (mut server, mut client) = handshake_pair(1, 2).await;

        let msg = Message::Get(GetRequest {
            resource_id: b"res".to_vec(),
            their_dvv: Dvv::from_write(nid(1), 1),
        });
        client.send(&msg, now()).await.expect("send get");

        let events = poll_until_event(&mut server, 500).await.unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Frame { tier, stream, msg } => {
                assert_eq!(*tier, Tier::Sync);
                assert_eq!(*stream, 4);
                assert_eq!(msg.verb().unwrap(), "get");
            }
            other => panic!("expected Frame on T1, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_receive_on_t3() {
        let (mut server, mut client) = handshake_pair(1, 2).await;

        let msg = Message::Emit(EmitEvent {
            event_type: "presence".into(),
            payload: CborValue::Int(42),
        });
        client.send(&msg, now()).await.expect("send emit");

        let events = poll_until_event(&mut server, 500).await.unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::Datagram { msg } => {
                assert_eq!(msg.tier, Tier::Event);
                assert_eq!(msg.verb().unwrap(), "emit");
            }
            other => panic!("expected Datagram, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capability_gate_rejects_governance_without_capability() {
        let (mut server, mut client) = handshake_pair(1, 2).await;

        let msg =
            Message::RegisterTcid(quip_core::messages::TrustedCidRegistration {
                cid: quip_core::cid::CidOrV1::Raw(quip_core::cid::Cid([0x10; 32])),
                app_metadata: vec![],
                owner: nid(1),
                timestamp: now(),
                signature: [0xef; 64],
            });
        let err = client.send(&msg, now()).await.expect_err("must reject");
        assert!(matches!(err, Error::CapabilityViolation { .. }));

        let events = poll_until_event(&mut server, 100).await.unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bulk_stream_opens_and_carries_chunks() {
        let (mut server, mut client) = handshake_pair(1, 2).await;

        let resource = b"my-resource".to_vec();
        let payload = b"hello world".to_vec();
        let digest = [0xab; 32];
        let cid = quip_core::cid::CidOrV1::Raw(quip_core::cid::Cid(digest));

        client
            .send(
                &Message::SendStart(message::SendStart {
                    resource_id: resource.clone(),
                    total_size: payload.len() as u64,
                    hash: digest.to_vec(),
                    cid,
                    hash_algo: None,
                }),
                now(),
            )
            .await
            .expect("send_start");

        let events = poll_until_event(&mut server, 500).await.unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::BulkStreamOpened { .. })),
            "expected BulkStreamOpened, got {events:?}"
        );

        client
            .send(
                &Message::SendChunk(message::SendChunk {
                    resource_id: resource.clone(),
                    seq: 0,
                    offset: 0,
                    bytes: payload.clone(),
                }),
                now(),
            )
            .await
            .expect("send_chunk");

        let mut saw_chunk = false;
        for _ in 0..10 {
            let events = poll_until_event(&mut server, 200).await.unwrap();
            for e in &events {
                if let Event::Frame { tier, msg, .. } = e {
                    if *tier == Tier::Bulk && msg.verb().unwrap() == "send_chunk" {
                        saw_chunk = true;
                    }
                }
            }
            if saw_chunk {
                break;
            }
        }
        assert!(saw_chunk, "server did not receive send_chunk");

        client
            .send(
                &Message::SendComplete(message::SendComplete {
                    resource_id: resource,
                    final_hash: digest.to_vec(),
                    cid: Some(cid),
                }),
                now(),
            )
            .await
            .expect("send_complete");
    }

    // ---- M5.4 behavior ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn key_claims_are_exchanged_and_stored() {
        let (server, client) = handshake_pair(1, 2).await;

        let client_sees = client
            .peer_key_claim()
            .expect("client stored the peer's claim");
        let server_sees = server
            .peer_key_claim()
            .expect("server stored the peer's claim");

        assert_eq!(client_sees.node_id, [1u8; 32], "client sees server's NodeId");
        assert_eq!(server_sees.node_id, [2u8; 32], "server sees client's NodeId");

        // Local claims are also exposed.
        assert_eq!(client.local_key_claim().node_id, [2u8; 32]);
        assert_eq!(server.local_key_claim().node_id, [1u8; 32]);

        // peer_node_id mirrors peer_key_claim.
        assert_eq!(client.peer_node_id(), Some([1u8; 32]));
        assert_eq!(server.peer_node_id(), Some([2u8; 32]));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn announce_key_does_not_surface_as_a_frame() {
        // The Key Claim exchange must happen before the read tasks
        // spawn, so the peer's announce_key is consumed internally and
        // never appears in the event stream.
        let (mut server, mut client) = handshake_pair(1, 2).await;

        // Poll both sides idle; there should be no leftover events from
        // the exchange.
        assert!(client.poll(now()).await.unwrap().is_empty());
        assert!(server.poll(now()).await.unwrap().is_empty());
    }

    // =====================================================================
    // M7 — rate limiting
    // =====================================================================

    /// The driver rejects surplus general ops once the peer exceeds its
    /// budget, surfacing each surplus as `Event::Error { RateLimit }`.
    ///
    /// Configure the server with a 3-op budget and no burst, then have
    /// the client send 10 `Error` frames on T0. The server should accept
    /// exactly 3 and rate-limit the remaining 7.
    ///
    /// The test uses a fixed `now`, so the bucket never refills during
    /// the run and the counts are deterministic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rate_limit_rejects_surplus_ops() {
        let (mut server, mut client) = handshake_pair(1, 2).await;

        // Configure the receiver with a tight budget.
        let cfg = RateLimiterConfig {
            general: BucketConfig {
                limit_per_minute: 3,
                burst: 0,
            },
            ..RateLimiterConfig::default()
        };
        server.set_rate_config(cfg);

        // The server must know the peer NodeId by now.
        assert_eq!(server.peer_node_id(), Some([2u8; 32]));

        // The client sends 10 messages on T0, all classified as
        // `OperationKind::General`.
        for i in 0..10u64 {
            let msg = Message::Error(message::ErrorMessage {
                code: quip_core::ErrorCode::Violation,
                message_id: i,
                text: "spam".into(),
            });
            client.send(&msg, now()).await.expect("send");
        }

        // Drain on the server side and count acceptances vs limits.
        let mut accepted = 0u64;
        let mut limited = 0u64;
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline && (accepted + limited) < 10 {
            let events = server.poll(now()).await.unwrap();
            for e in events {
                match e {
                    Event::Frame { .. } => accepted += 1,
                    Event::Error {
                        error: Error::RateLimit,
                        ..
                    } => limited += 1,
                    _ => {}
                }
            }
        }

        assert_eq!(accepted, 3, "expected exactly 3 accepted frames");
        assert_eq!(limited, 7, "expected exactly 7 rate-limit errors");
    }

    /// T2 (bulk) traffic is exempt from the ops/min limiter.
    ///
    /// Configure the server with a 1-op general budget, then send a
    /// small bulk transfer (4 chunks). The transfer should complete
    /// without any `RateLimit` errors.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rate_limit_exempts_bulk() {
        let (mut server, mut client) = handshake_pair(1, 2).await;

        // A budget of 1 op is below what the handshake already
        // consumed, but bulk frames must not be limited at all.
        let cfg = RateLimiterConfig {
            general: BucketConfig {
                limit_per_minute: 1,
                burst: 0,
            },
            ..RateLimiterConfig::default()
        };
        server.set_rate_config(cfg);

        let resource = b"bulk-exempt".to_vec();
        let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let digest = [0u8; 32];
        let cid = quip_core::cid::CidOrV1::Raw(quip_core::cid::Cid(digest));

        client
            .send(
                &Message::SendStart(message::SendStart {
                    resource_id: resource.clone(),
                    total_size: payload.len() as u64,
                    hash: digest.to_vec(),
                    cid,
                    hash_algo: None,
                }),
                now(),
            )
            .await
            .expect("send_start");

        for (i, chunk) in payload.chunks(1024).enumerate() {
            client
                .send(
                    &Message::SendChunk(message::SendChunk {
                        resource_id: resource.clone(),
                        seq: i as u64,
                        offset: (i * 1024) as u64,
                        bytes: chunk.to_vec(),
                    }),
                    now(),
                )
                .await
                .expect("send_chunk");
        }

        client
            .send(
                &Message::SendComplete(message::SendComplete {
                    resource_id: resource,
                    final_hash: digest.to_vec(),
                    cid: Some(cid),
                }),
                now(),
            )
            .await
            .expect("send_complete");

        // Collect. Every bulk frame should arrive without a RateLimit
        // error.
        let mut bulk_frames = 0u64;
        let mut rate_errors = 0u64;
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline && bulk_frames < 6 {
            let events = server.poll(now()).await.unwrap();
            for e in events {
                match e {
                    Event::Frame {
                        tier: Tier::Bulk, ..
                    } => bulk_frames += 1,
                    Event::Error {
                        error: Error::RateLimit,
                        ..
                    } => rate_errors += 1,
                    _ => {}
                }
            }
        }

        assert_eq!(bulk_frames, 6, "expected 6 bulk frames (start + 4 + complete)");
        assert_eq!(rate_errors, 0, "bulk frames must not be rate-limited");
    }

    // =====================================================================
    // M6.1 — §16 full-flow integration tests
    // =====================================================================

    use crate::bulk::BulkReceiver;
    use quip_core::cid::{Cid, CidOrV1, HashAlgo};
    use quip_storage::ContentHasher;

    /// Poll `driver` until `pred` matches an event, or the deadline
    /// expires. Returns the matching event on success, `None` on
    /// timeout. Non-matching events are discarded.
    async fn poll_for_event<F>(
        driver: &mut ConnectionDriver,
        timeout_ms: u64,
        mut pred: F,
    ) -> Option<Event>
    where
        F: FnMut(&Event) -> bool,
    {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let events = driver.poll(now()).await.ok()?;
            for e in events {
                if pred(&e) {
                    return Some(e);
                }
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
        }
    }

    /// True if `event` is a T0/T1/T2 frame carrying the given verb.
    fn is_frame_with_verb(event: &Event, tier: Tier, verb: &str) -> bool {
        matches!(
            event,
            Event::Frame { tier: t, msg, .. }
                if *t == tier && msg.verb().map(|v| v == verb).unwrap_or(false)
        )
    }

    // ---- Stage 4 — full bulk transfer with CID verification ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bulk_full_transfer_verifies_cid() {
        let (mut server, mut client) = handshake_pair(1, 2).await;

        let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let hasher = crate::crypto::Sha256Hasher;
        let digest = hasher.digest(HashAlgo::Sha256, &payload).unwrap();
        let cid = CidOrV1::Raw(Cid(digest));
        let resource = b"stage4-resource".to_vec();

        // Client sends the entire transfer up front, before the server
        // polls. This eliminates the race between the server's read
        // task spawning and the arrival of the first chunk.
        client
            .send(
                &Message::SendStart(message::SendStart {
                    resource_id: resource.clone(),
                    total_size: payload.len() as u64,
                    hash: digest.to_vec(),
                    cid,
                    hash_algo: None,
                }),
                now(),
            )
            .await
            .expect("send_start");

        const CHUNK: usize = 1024;
        let mut seq = 0u64;
        let mut offset = 0usize;
        while offset < payload.len() {
            let end = (offset + CHUNK).min(payload.len());
            client
                .send(
                    &Message::SendChunk(message::SendChunk {
                        resource_id: resource.clone(),
                        seq,
                        offset: offset as u64,
                        bytes: payload[offset..end].to_vec(),
                    }),
                    now(),
                )
                .await
                .expect("send_chunk");
            seq += 1;
            offset = end;
        }

        client
            .send(
                &Message::SendComplete(message::SendComplete {
                    resource_id: resource.clone(),
                    final_hash: digest.to_vec(),
                    cid: Some(cid),
                }),
                now(),
            )
            .await
            .expect("send_complete");

        // Now collect on the server side. The deadline is generous
        // because the runtime may be loaded with other tests.
        let mut receiver = BulkReceiver::new();
        let mut done = false;
        let mut opened = false;
        let deadline = std::time::Instant::now() + Duration::from_millis(10_000);
        while std::time::Instant::now() < deadline && !done {
            let events = server.poll(now()).await.unwrap();
            for e in events {
                match e {
                    Event::BulkStreamOpened { .. } => {
                        opened = true;
                    }
                    Event::Frame {
                        tier: Tier::Bulk,
                        msg,
                        ..
                    } => {
                        let complete = receiver.ingest_bytes(&msg.raw).unwrap();
                        if complete {
                            done = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        assert!(opened, "server did not see BulkStreamOpened");
        assert!(done, "server never finished the bulk transfer");

        let reassembled = receiver
            .reassemble_verified(HashAlgo::Sha256, &hasher)
            .expect("verified reassembly");
        assert_eq!(reassembled, payload, "reassembled bytes match payload");
    }

    // ---- Stage 5 — fetch_range / range_response with bao verification ----

    #[cfg(feature = "crypto")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fetch_range_round_trip_with_proof() {
        use crate::range::bao_support::{extract_proof, verify_response};
        use crate::range::{FetchRange, RangeResponse};

        let caps = Capabilities::baseline()
            | Capabilities(Capabilities::BLAKE3)
            | Capabilities(Capabilities::CID_ADDRESSING)
            | Capabilities(Capabilities::MERKLE_RANGE);
        let (mut server, mut client) = handshake_pair_with(1, 2, caps).await;

        // Sanity: both sides agreed on the capability.
        let agreed = client.agreed().expect("client agreed");
        assert!(agreed.has(Capabilities::MERKLE_RANGE));

        // A BLAKE3-addressed 8 KiB payload.
        let payload: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        let hasher = crate::crypto::Blake3Hasher;
        let digest = hasher.digest(HashAlgo::Blake3, &payload).unwrap();
        let cid = CidOrV1::V1(quip_core::cid::CidV1 {
            hash_algo: HashAlgo::Blake3,
            digest,
        });
        let resource = b"stage5-resource".to_vec();
        let offset = 1000u64;
        let length = 2048u64;

        // --- Client asks ---
        client
            .send(
                &Message::FetchRange(FetchRange {
                    resource_id: resource.clone(),
                    cid,
                    offset,
                    length,
                }),
                now(),
            )
            .await
            .expect("fetch_range");

        // --- Server sees the request ---
        let req = poll_for_event(&mut server, 500, |e| {
            is_frame_with_verb(e, Tier::Sync, "fetch_range")
        })
        .await
        .expect("server did not see fetch_range");
        match &req {
            Event::Frame { tier, msg, .. } => {
                assert_eq!(*tier, Tier::Sync);
                assert_eq!(msg.verb().unwrap(), "fetch_range");
            }
            _ => unreachable!(),
        }

        // --- Server computes the response locally ---
        // (In a real deployment this is a state-machine concern; here
        // the test acts as the responder.)
        let (bytes, proof) = extract_proof(&payload, offset, length).expect("extract_proof");
        assert_eq!(bytes.len() as u64, length);
        assert_eq!(
            bytes,
            payload[offset as usize..(offset + length) as usize].to_vec()
        );

        server
            .send(
                &Message::RangeResponse(RangeResponse {
                    resource_id: resource.clone(),
                    cid,
                    offset,
                    length,
                    bytes: bytes.clone(),
                    proof,
                }),
                now(),
            )
            .await
            .expect("range_response");

        // --- Client sees it and verifies the proof ---
        let resp_event = poll_for_event(&mut client, 500, |e| {
            is_frame_with_verb(e, Tier::Sync, "range_response")
        })
        .await
        .expect("client did not see range_response");

        // Decode the range_response from the raw bytes.
        let raw = match resp_event {
            Event::Frame { msg, .. } => msg.raw,
            _ => unreachable!(),
        };
        let resp = RangeResponse::from_bytes(&raw).expect("decode range_response");
        verify_response(&resp, HashAlgo::Blake3).expect("bao proof verifies");
        assert_eq!(resp.bytes, bytes);
        assert_eq!(resp.offset, offset);
        assert_eq!(resp.length, length);
    }

    // ---- Stage 6 — governance verbs on T0 ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn governance_register_tcid_round_trips() {
        let caps = Capabilities::baseline()
            | Capabilities(Capabilities::CID_ADDRESSING)
            | Capabilities(Capabilities::DHT_DISCOVERY)
            | Capabilities(Capabilities::GOVERNANCE);
        let (mut server, mut client) = handshake_pair_with(1, 2, caps).await;

        // Sanity: the negotiated set includes GOVERNANCE.
        assert!(client.agreed().unwrap().has(Capabilities::GOVERNANCE));

        let registration = quip_core::messages::TrustedCidRegistration {
            cid: CidOrV1::Raw(Cid([0x10; 32])),
            app_metadata: vec![],
            owner: nid(2),
            timestamp: now(),
            signature: [0xef; 64],
        };

        client
            .send(&Message::RegisterTcid(registration), now())
            .await
            .expect("register_tcid");

        let seen = poll_for_event(&mut server, 500, |e| {
            is_frame_with_verb(e, Tier::Ctrl, "register_tcid")
        })
        .await;
        assert!(seen.is_some(), "server did not see register_tcid");
    }

    // ---- Stage 7 — BFT verbs on T0 ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bft_consensus_sequence_round_trips() {
        use crate::bft::{BftCommit, BftPrecommit, BftPrepare, BftPreprepare, Operation};
        use alloc::string::String;

        let (mut server, mut client) = handshake_pair(1, 2).await;

        let ring_id = [0xAA; 32];
        let digest = [0xBB; 32];
        let operation = Operation {
            kind: String::from("key_rotation"),
            subject: vec![0x01; 32],
            body: CborValue::Int(1),
        };

        // preprepare, then the three votes, in sequence.
        client
            .send(
                &Message::BftPreprepare(BftPreprepare {
                    ring_id,
                    view: 0,
                    sequence: 0,
                    operation,
                    digest,
                    primary_sig: [0xCC; 64],
                }),
                now(),
            )
            .await
            .expect("bft_preprepare");

        for msg in [
            Message::BftPrepare(BftPrepare {
                ring_id,
                view: 0,
                sequence: 0,
                digest,
                witness_sig: [0xDD; 64],
            }),
            Message::BftPrecommit(BftPrecommit {
                ring_id,
                view: 0,
                sequence: 0,
                digest,
                witness_sig: [0xDD; 64],
            }),
            Message::BftCommit(BftCommit {
                ring_id,
                view: 0,
                sequence: 0,
                digest,
                witness_sig: [0xDD; 64],
            }),
        ] {
            client.send(&msg, now()).await.expect("bft vote");
        }

        // Server should see four T0 events, one per verb.
        let mut seen = std::collections::BTreeSet::new();
        let deadline = std::time::Instant::now() + Duration::from_millis(2000);
        while std::time::Instant::now() < deadline && seen.len() < 4 {
            let events = server.poll(now()).await.unwrap();
            for e in events {
                if let Event::Frame {
                    tier: Tier::Ctrl,
                    msg,
                    ..
                } = e
                {
                    seen.insert(msg.verb().unwrap().to_string());
                }
            }
        }

        for expected in [
            "bft_preprepare",
            "bft_prepare",
            "bft_precommit",
            "bft_commit",
        ] {
            assert!(seen.contains(expected), "server did not see {expected}");
        }
    }

    // ---- Stage 8 — cross-path validation on T0 ----

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_path_validation_round_trips() {
        use crate::coral::{CrossPathValidation, LookupResponse, PathProof};

        let caps = Capabilities::baseline() | Capabilities(Capabilities::DHT_DISCOVERY);
        let (mut server, mut client) = handshake_pair_with(1, 2, caps).await;

        // Build a CrossPathValidation with one embedded LookupResponse.
        // The embedded response carries a nonzero signature so the test
        // exercises the nested-signature path in §10.1.
        let inner = LookupResponse {
            key: [0x10; 32],
            values: vec![],
            path_proofs: vec![PathProof {
                path_id: [0x20; 16],
                node_signatures: vec![],
                value_hash: [0x30; 32],
                responded: false,
            }],
            responder: nid(3),
            timestamp: now(),
            signature: [0x44; 64],
        };
        let check = CrossPathValidation {
            key: [0x11; 32],
            path_responses: vec![inner],
            witness_ring: vec![nid(1), nid(2), nid(3)],
            requester: nid(2),
            timestamp: now(),
            signature: [0x22; 64],
        };

        client
            .send(&Message::CrossPathValidation(check), now())
            .await
            .expect("cross_path_validation");

        let seen = poll_for_event(&mut server, 500, |e| {
            is_frame_with_verb(e, Tier::Ctrl, "cross_path_validation")
        })
        .await;
        assert!(seen.is_some(), "server did not see cross_path_validation");
    }
}