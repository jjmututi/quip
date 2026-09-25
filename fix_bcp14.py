#!/usr/bin/env python3
import re

KEYWORDS = {
    "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
    "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
    "MAY", "OPTIONAL",
}

PATTERN = re.compile(r"<bcp14>(.*?)</bcp14>", re.DOTALL)
STRIP_TAGS = re.compile(r"<[^>]+>")

def is_keyword(body):
    # strip any nested markup (<tt>, <xref>, …) and whitespace
    text = STRIP_TAGS.sub("", body).strip()
    return text in KEYWORDS

with open("draft-mututi-quip-03.xml", "r", encoding="utf-8") as f:
    src = f.read()

kept = 0
changed = 0

def replace(match):
    global kept, changed
    body = match.group(1)
    if is_keyword(body):
        kept += 1
        return match.group(0)
    changed += 1
    return f"<strong>{body}</strong>"

out = PATTERN.sub(replace, src)

with open("draft-mututi-quip-03.xml", "w", encoding="utf-8") as f:
    f.write(out)

print(f"kept <bcp14> (real keywords): {kept}")
print(f"converted to <strong>:       {changed}")
