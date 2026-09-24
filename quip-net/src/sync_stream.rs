//! T1 SYNC stream state machine (§11).
//!
//! T1 (QUIC stream 4) carries five request verbs: `get`, `set`, `sync`,
//! `rbsr_sync`, and `fetch_range`. Each request transitions the stream
//! into a state named for the verb being served; each response returns
//! the stream to `Idle`, awaiting the next request.
//!
//! # States
//!
//! | State | Entered when |
//! |---|---|
//! | `Initial` | the stream opens; no request received |
//! | `Syncing` | a `get`, `set`, or `sync` was received |
//! | `RbsrSyncing` | an `rbsr_sync` was received |
//! | `RangeFetching` | a `fetch_range` was received |
//! | `Idle` | a response was sent; ready for the next request |
//! | `Error` | a protocol error occurred; terminal |
//!
//! `Error` is absorbing: once entered, no further event changes the state.
//!
//! # Who drives it
//!
//! The state machine is passive. `SyncStream::on_event` feeds it one
//! event; the caller decides what to do with the resulting state. The
//! transport driver consults it to know whether the stream is currently
//! busy, and rejects a request that arrives while one is in flight.
//!
//! # Not in scope
//!
//! The state machine does not own the request data, does not schedule
//! responses, and does not enforce per-state timeouts.

use crate::error::{Error, Result};
use alloc::string::String;

/// The state of the T1 SYNC stream.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum SyncState {
    /// No request in flight; the stream is open but idle.
    #[default]
    Initial,
    /// Serving a `get`, `set`, or `sync` request.
    Syncing,
    /// Serving an `rbsr_sync` request.
    RbsrSyncing,
    /// Serving a `fetch_range` request.
    RangeFetching,
    /// A request was served; awaiting the next.
    Idle,
    /// Terminal error state.
    Error,
}

impl SyncState {
    /// True for `Idle` and `Initial`, which both accept a new request.
    pub fn is_ready(self) -> bool {
        matches!(self, SyncState::Initial | SyncState::Idle)
    }

    /// True when a request is currently being served.
    pub fn is_busy(self) -> bool {
        matches!(
            self,
            SyncState::Syncing | SyncState::RbsrSyncing | SyncState::RangeFetching
        )
    }

    /// True for `Error`.
    pub fn is_terminal(self) -> bool {
        matches!(self, SyncState::Error)
    }
}

/// An event that moves the SYNC stream state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncEvent {
    /// A `get`, `set`, or `sync` was received.
    RecvDvv,
    /// An `rbsr_sync` was received.
    RecvRbsrSync,
    /// A `fetch_range` was received.
    RecvFetchRange,
    /// The response for the current request was sent.
    ResponseSent,
    /// A protocol error occurred. Carries a short description.
    ProtocolError(String),
    /// The stream closed, by either peer.
    StreamClosed,
}

/// The T1 SYNC stream state machine.
#[derive(Clone, Debug, Default)]
pub struct SyncStream {
    state: SyncState,
    requests_handled: u64,
    last_event: Option<SyncEvent>,
    error_text: Option<String>,
}

impl SyncStream {
    /// A fresh state machine in `Initial`.
    pub fn new() -> Self {
        Self::default()
    }

    /// The current state.
    pub fn state(&self) -> SyncState {
        self.state
    }

    /// Number of requests fully served.
    pub fn requests_handled(&self) -> u64 {
        self.requests_handled
    }

    /// The last event fed in, if any.
    pub fn last_event(&self) -> Option<&SyncEvent> {
        self.last_event.as_ref()
    }

    /// The error text, if the machine is in `Error`.
    pub fn error_text(&self) -> Option<&str> {
        self.error_text.as_deref()
    }

    /// True when the machine has reached `Error`.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// True when the machine can accept a new request.
    pub fn is_ready(&self) -> bool {
        self.state.is_ready()
    }

    /// Feed one event into the machine.
    pub fn on_event(&mut self, event: SyncEvent) -> Result<SyncState> {
        if self.state == SyncState::Error {
            self.last_event = Some(event);
            return Ok(SyncState::Error);
        }

        if let SyncEvent::ProtocolError(text) = &event {
            self.state = SyncState::Error;
            self.error_text = Some(text.clone());
            self.last_event = Some(event);
            return Ok(self.state);
        }

        if matches!(event, SyncEvent::StreamClosed) {
            self.state = SyncState::Error;
            self.error_text = Some(String::from("stream closed"));
            self.last_event = Some(event);
            return Ok(self.state);
        }

        let next = match (self.state, &event) {
            (state, SyncEvent::RecvDvv) if state.is_ready() => SyncState::Syncing,
            (state, SyncEvent::RecvRbsrSync) if state.is_ready() => SyncState::RbsrSyncing,
            (state, SyncEvent::RecvFetchRange) if state.is_ready() => SyncState::RangeFetching,
            (state, SyncEvent::ResponseSent) if state.is_busy() => {
                self.requests_handled = self.requests_handled.saturating_add(1);
                SyncState::Idle
            }
            (
                state,
                SyncEvent::RecvDvv | SyncEvent::RecvRbsrSync | SyncEvent::RecvFetchRange,
            ) if state.is_busy() => {
                self.last_event = Some(event);
                return Err(Error::BadStream(
                    "request received while a T1 request is in flight",
                ));
            }
            (_, SyncEvent::ResponseSent) => {
                self.last_event = Some(event);
                return Err(Error::BadStream(
                    "response sent with no T1 request in flight",
                ));
            }
            _ => self.state,
        };

        self.state = next;
        self.last_event = Some(event);
        Ok(self.state)
    }

    /// Reset to `Initial`.
    pub fn reset(&mut self) {
        self.state = SyncState::Initial;
        self.requests_handled = 0;
        self.last_event = None;
        self.error_text = None;
    }

    /// Classify a verb string into the state-transition event it
    /// represents, if it is a SYNC *request* verb.
    ///
    /// Returns `None` for responses and for non-SYNC verbs. The
    /// transport driver feeds `ResponseSent` explicitly when it sends a
    /// response, since `get` / `set` / `sync` responses reuse the
    /// request verb and cannot be distinguished from the verb alone.
    pub fn classify_verb(verb: &str) -> Option<SyncEvent> {
        match verb {
            "get" | "set" | "sync" => Some(SyncEvent::RecvDvv),
            "rbsr_sync" => Some(SyncEvent::RecvRbsrSync),
            "fetch_range" => Some(SyncEvent::RecvFetchRange),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_machine_is_initial_and_ready() {
        let m = SyncStream::new();
        assert_eq!(m.state(), SyncState::Initial);
        assert!(m.is_ready());
        assert!(!m.state().is_busy());
        assert!(!m.is_terminal());
        assert_eq!(m.requests_handled(), 0);
        assert!(m.last_event().is_none());
    }

    #[test]
    fn request_from_initial_enters_the_matching_state() {
        let mut m = SyncStream::new();
        assert_eq!(m.on_event(SyncEvent::RecvDvv).unwrap(), SyncState::Syncing);
        m.reset();
        assert_eq!(
            m.on_event(SyncEvent::RecvRbsrSync).unwrap(),
            SyncState::RbsrSyncing
        );
        m.reset();
        assert_eq!(
            m.on_event(SyncEvent::RecvFetchRange).unwrap(),
            SyncState::RangeFetching
        );
    }

    #[test]
    fn response_returns_to_idle_and_counts_the_request() {
        let mut m = SyncStream::new();
        m.on_event(SyncEvent::RecvDvv).unwrap();
        assert_eq!(m.on_event(SyncEvent::ResponseSent).unwrap(), SyncState::Idle);
        assert_eq!(m.requests_handled(), 1);
    }

    #[test]
    fn idle_accepts_a_new_request() {
        let mut m = SyncStream::new();
        m.on_event(SyncEvent::RecvDvv).unwrap();
        m.on_event(SyncEvent::ResponseSent).unwrap();
        assert_eq!(m.on_event(SyncEvent::RecvDvv).unwrap(), SyncState::Syncing);
        m.on_event(SyncEvent::ResponseSent).unwrap();
        assert_eq!(m.requests_handled(), 2);
    }

    #[test]
    fn request_while_busy_is_rejected() {
        let mut m = SyncStream::new();
        m.on_event(SyncEvent::RecvDvv).unwrap();
        let err = m.on_event(SyncEvent::RecvFetchRange).unwrap_err();
        assert!(matches!(err, Error::BadStream(_)), "got {err:?}");
        assert_eq!(m.state(), SyncState::Syncing);
    }

    #[test]
    fn response_with_no_request_is_rejected() {
        let mut m = SyncStream::new();
        let err = m.on_event(SyncEvent::ResponseSent).unwrap_err();
        assert!(matches!(err, Error::BadStream(_)), "got {err:?}");
    }

    #[test]
    fn protocol_error_is_terminal() {
        let mut m = SyncStream::new();
        m.on_event(SyncEvent::ProtocolError("bad arity".into()))
            .unwrap();
        assert_eq!(m.state(), SyncState::Error);
        assert!(m.is_terminal());
        assert_eq!(m.error_text(), Some("bad arity"));
    }

    #[test]
    fn error_is_absorbing() {
        let mut m = SyncStream::new();
        m.on_event(SyncEvent::ProtocolError("x".into())).unwrap();
        assert_eq!(m.on_event(SyncEvent::RecvDvv).unwrap(), SyncState::Error);
        assert_eq!(
            m.on_event(SyncEvent::ResponseSent).unwrap(),
            SyncState::Error
        );
    }

    #[test]
    fn stream_closed_is_terminal() {
        let mut m = SyncStream::new();
        m.on_event(SyncEvent::StreamClosed).unwrap();
        assert_eq!(m.state(), SyncState::Error);
        assert_eq!(m.error_text(), Some("stream closed"));
    }

    #[test]
    fn reset_returns_to_initial() {
        let mut m = SyncStream::new();
        m.on_event(SyncEvent::RecvDvv).unwrap();
        m.on_event(SyncEvent::ResponseSent).unwrap();
        m.reset();
        assert_eq!(m.state(), SyncState::Initial);
        assert_eq!(m.requests_handled(), 0);
    }

    #[test]
    fn full_request_response_cycle() {
        let mut m = SyncStream::new();
        for _ in 0..5 {
            m.on_event(SyncEvent::RecvDvv).unwrap();
            assert!(m.state().is_busy());
            m.on_event(SyncEvent::ResponseSent).unwrap();
            assert!(m.state().is_ready());
        }
        assert_eq!(m.requests_handled(), 5);
    }

    #[test]
    fn classify_verb_matches_the_dvv_and_range_verbs() {
        assert_eq!(SyncStream::classify_verb("get"), Some(SyncEvent::RecvDvv));
        assert_eq!(SyncStream::classify_verb("set"), Some(SyncEvent::RecvDvv));
        assert_eq!(SyncStream::classify_verb("sync"), Some(SyncEvent::RecvDvv));
        assert_eq!(
            SyncStream::classify_verb("rbsr_sync"),
            Some(SyncEvent::RecvRbsrSync)
        );
        assert_eq!(
            SyncStream::classify_verb("fetch_range"),
            Some(SyncEvent::RecvFetchRange)
        );
        assert_eq!(SyncStream::classify_verb("range_response"), None);
        assert_eq!(SyncStream::classify_verb("send_start"), None);
        assert_eq!(SyncStream::classify_verb(""), None);
    }
}