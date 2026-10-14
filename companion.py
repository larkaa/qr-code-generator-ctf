#!/usr/bin/env python3
"""
companion.py -- terminal client for the MyCompanion chat API.

Reverse-engineered flow (see NOTES.md):

  1. GET  /api/session/access-token          cookies only  -> fresh 15-min JWT
  2. POST /api/companion/messages            {conversationId, prompt} -> user message id
  3. POST /api/companion/messages/{id}/chat  empty body, Accept: text/event-stream -> SSE answer

So the only things you need from a logged-in browser are the cookies.
The bearer token is minted by the script (and refreshed automatically).

Usage:
    ./companion.py probe                      # verify credentials / discover shapes
    ./companion.py                            # interactive REPL
    ./companion.py ask "hello"                # one-shot, answer to stdout
    ./companion.py import-curl request.curl   # harvest cookies+token from a copied curl

Stdlib only. Python 3.9+.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid as uuidlib

try:                       # optional: line editing + history in the REPL
    import readline  # noqa: F401
except ImportError:
    readline = None

DEFAULT_BASE = "https://mycompanion.group.echonet"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.0.0"
)
CONFIG_PATH = os.environ.get(
    "COMPANION_CONFIG",
    os.path.join(os.path.expanduser("~"), ".config", "companion", "config.json"),
)
HISTORY_PATH = os.path.join(os.path.expanduser("~"), ".config", "companion", "history")

UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")

# Keys we look at when hunting a value inside an unknown JSON payload.
TOKEN_KEYS = ("access_token", "accessToken", "token", "id_token", "idToken", "jwt")
ID_KEYS = ("id", "messageId", "message_id", "uuid", "messageUuid")
LIST_KEYS = ("items", "conversations", "results", "data", "content", "hits", "rows")
TITLE_KEYS = ("title", "name", "label", "subject", "summary", "firstPrompt", "prompt")
CONTENT_KEYS = ("content", "delta", "text", "answer", "chunk", "token",
                "partial", "output", "value", "completion")


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def eprint(*a, **kw):
    print(*a, file=sys.stderr, **kw)


def walk(obj, depth=0):
    """Breadth-ish recursive walk yielding (depth, key, value)."""
    if depth > 8:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield depth, k, v
            yield from walk(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v, depth + 1)


def find_key(obj, keys, *, value_test=None, avoid=()):
    """Find the shallowest value stored under one of `keys` (in priority order)."""
    best = None
    for depth, key, value in walk(obj):
        if key in keys and not any(b in key.lower() for b in avoid):
            if value_test is not None and not value_test(value):
                continue
            rank = (keys.index(key) if key in keys else 99, depth)
            if best is None or rank < best[0]:
                best = (rank, value)
    return best[1] if best else None


def parse_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def jwt_claims(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def parse_cookie_string(raw):
    out = {}
    for pair in re.split(r"[;\n]", raw or ""):
        pair = pair.strip()
        if not pair or pair.startswith("#") or "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        k, v = k.strip(), v.strip().strip('"')
        if k.lower() in ("cookie", "$cookie"):
            continue
        out[k] = v
    return out


def load_curl_text(text):
    """Pull cookies / bearer / useful headers out of a 'Copy as cURL' blob."""
    text = text.replace("\\\n", " ")
    cookies, token, referer = {}, None, None
    for m in re.finditer(r"(?:-b|--cookie|--cookie-jar)\s+'([^']*)'", text):
        cookies.update(parse_cookie_string(m.group(1)))
    for m in re.finditer(r"(?:authorization|x-token)\s*:\s*(?:Bearer\s+)?([A-Za-z0-9._\-]{20,})",
                         text, re.I):
        if JWT_RE.fullmatch(m.group(1)) or JWT_RE.search(m.group(1)):
            token = m.group(1)
    m = re.search(r"referer\s*:\s*(\S+)", text, re.I)
    if m:
        referer = m.group(1).rstrip("'\"")
    return cookies, token, referer


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
class Config:
    def __init__(self, base=DEFAULT_BASE, cookies="", token="", conversation=None,
                 referer=None, sse_path=None, insecure=False):
        self.base = base.rstrip("/")
        self.cookies = cookies
        self.token = token
        self.conversation = conversation
        self.referer = referer or (self.base + "/")
        self.sse_path = sse_path
        self.insecure = insecure

    @classmethod
    def load(cls):
        cfg = cls()
        if os.path.exists(CONFIG_PATH):
            data = parse_json(open(CONFIG_PATH, encoding="utf-8").read()) or {}
            cfg.base = data.get("base_url", cfg.base)
            cfg.cookies = data.get("cookies", cfg.cookies)
            cfg.token = data.get("token", cfg.token)
            cfg.conversation = data.get("conversation_id")
            cfg.referer = data.get("referer", cfg.base + "/")
            cfg.sse_path = data.get("sse_path")
            cfg.insecure = bool(data.get("insecure", False))
        cfg.cookies = os.environ.get("COMPANION_COOKIES", cfg.cookies)
        cfg.token = os.environ.get("COMPANION_TOKEN", cfg.token)
        return cfg

    def save(self):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
            json.dump({
                "base_url": self.base,
                "cookies": self.cookies,
                "token": self.token,
                "conversation_id": self.conversation,
                "referer": self.referer,
                "sse_path": self.sse_path,
                "insecure": self.insecure,
            }, fh, indent=2)
        os.chmod(CONFIG_PATH, 0o600)
        eprint(f"[saved -> {CONFIG_PATH}]")


# --------------------------------------------------------------------------- #
# errors
# --------------------------------------------------------------------------- #
class ApiError(Exception):
    def __init__(self, msg, status=None, body=None):
        super().__init__(msg)
        self.status = status
        self.body = body


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #
class Api:
    def __init__(self, cfg, verbose=False):
        self.cfg = cfg
        self.verbose = verbose
        self.token = cfg.token or None
        self.token_exp = jwt_claims(self.token).get("exp") if self.token else None
        self.cookies = parse_cookie_string(cfg.cookies)
        self._ctx = (ssl._create_unverified_context() if cfg.insecure
                     else ssl.create_default_context())

    # -- low level ---------------------------------------------------------- #
    def _headers(self, extra=None, *, accept="application/json, text/plain, */*",
                 auth=True, body=False, ctype=None):
        h = {
            "accept": accept,
            "accept-language": "en",
            "user-agent": USER_AGENT,
            "x-platform-origin": "companion",
            "origin": self.cfg.base,
            "referer": self.cfg.referer,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
        }
        if self.cookies:
            h["cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if auth and self.token:
            h["authorization"] = f"Bearer {self.token}"
        if body:
            h["content-length"] = "0"
        if ctype:
            h["content-type"] = ctype
        if extra:
            h.update({k.lower(): v for k, v in extra.items()})
        return h

    def _send(self, method, path, *, headers, data=None, timeout=60):
        url = self.cfg.base + path
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        if self.verbose:
            eprint(f"    > {method} {path}"
                   f"{' body=' + data.decode()[:200] if data else ''}")
        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=self._ctx)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace") if exc.fp else ""
            return exc.code, dict(exc.headers.items()), body
        except urllib.error.URLError as exc:
            raise ApiError(f"cannot reach {url}: {exc.reason}") from exc
        raw = resp.read().decode("utf-8", "replace")
        return resp.status, dict(resp.headers.items()), raw

    # -- auth --------------------------------------------------------------- #
    def token_valid(self, skew=60):
        return bool(self.token and self.token_exp and self.token_exp - time.time() > skew)

    def refresh_token(self, force=False):
        """Mint a fresh access token from the browser session cookies."""
        if self.token_valid() and not force:
            return self.token
        if not self.cookies:
            if self.token:
                return self.token
            raise ApiError("no cookies available: pass --cookies / --curl-file or "
                           "run 'companion.py import-curl'")
        status, _, body = self._send(
            "GET", "/api/session/access-token",
            headers=self._headers(auth=False))
        if status == 401:
            raise ApiError("access-token endpoint returned 401: your browser session "
                           "cookies are expired or missing. Re-login and re-export them.",
                           status, body)
        if status >= 400:
            raise ApiError(f"access-token endpoint returned {status}: {body[:300]}",
                           status, body)
        tok = None
        parsed = parse_json(body)
        if parsed is not None:
            tok = find_key(parsed, TOKEN_KEYS, value_test=lambda v: isinstance(v, str))
        if not tok:
            m = JWT_RE.search(body)
            tok = m.group(0) if m else None
        if not tok:
            raise ApiError(f"could not find a JWT in access-token response: {body[:300]}")
        self.token = tok
        self.token_exp = jwt_claims(tok).get("exp")
        self.cfg.token = tok
        if self.verbose:
            left = int(self.token_exp - time.time()) if self.token_exp else "?"
            eprint(f"    [token refreshed, {left}s left]")
        return tok

    def request(self, method, path, *, json_body=None, raw_body=None, headers=None,
                accept="application/json, text/plain, */*", ctype=None, tries=2):
        """Authenticated request with one automatic token refresh on 401."""
        for attempt in range(tries):
            self.refresh_token()
            hdrs = self._headers(headers, accept=accept)
            data = None
            if json_body is not None:
                data = json.dumps(json_body, ensure_ascii=False).encode()
                hdrs["content-type"] = ctype or "application/json"
            elif raw_body is not None:
                data = raw_body if isinstance(raw_body, bytes) else raw_body.encode()
                if ctype:
                    hdrs["content-type"] = ctype
            elif method.upper() in ("POST", "PATCH", "PUT"):
                hdrs["content-length"] = "0"
                if ctype:
                    hdrs["content-type"] = ctype
            status, rhdr, body = self._send(method, path, headers=hdrs, data=data)
            ctype_hdr = (rhdr.get("content-type") or rhdr.get("Content-Type") or "")
            if status == 200 and "text/html" in ctype_hdr and "/api/" in path:
                raise ApiError("got an HTML page instead of JSON -- the SSO session "
                               "cookies were rejected (re-login in the browser, then "
                               "re-export cookies).", status, body[:400])
            if status == 401 and attempt == 0:
                self.token = None  # force refresh and retry once
                continue
            return status, rhdr, body
        raise ApiError("unauthorized (401) after token refresh", status, body)

    # -- endpoints ---------------------------------------------------------- #
    def whoami(self):
        return self.request("GET", "/api/account/me")

    def list_conversations(self, limit=15):
        status, _, body = self.request("GET", f"/api/companion/conversations?limit={limit}")
        if status >= 400:
            raise ApiError(f"list conversations -> {status}: {body[:300]}", status, body)
        data = parse_json(body)
        items = None
        if isinstance(data, list):
            items = data
        elif data is not None:
            for _, key, value in walk(data):
                if key in LIST_KEYS and isinstance(value, list) and value:
                    items = value
                    break
        if items is None:  # last resort: any list of dicts carrying an id
            for _, key, value in walk(data):
                if (isinstance(value, list) and value and isinstance(value[0], dict)
                        and any(k in value[0] for k in ID_KEYS)):
                    items = value
                    break
        return items or [], body

    def get_conversation(self, cid):
        return self.request("GET", f"/api/companion/conversations/{cid}")

    def get_message(self, mid):
        return self.request("GET", f"/api/companion/messages/{mid}")

    def create_conversation(self):
        """Try the REST-ish create endpoint, fall back to a client-side UUID."""
        attempts = (("/api/companion/conversations", {}, None),
                    ("/api/companion/conversations", None, "application/x-www-form-urlencoded"))
        for path, json_body, ctype in attempts:
            try:
                status, _, body = self.request("POST", path, json_body=json_body,
                                               raw_body=b"" if json_body is None else None,
                                               ctype=ctype)
            except ApiError:
                continue
            if status < 300:
                cid = find_key(parse_json(body) or {}, ID_KEYS,
                               value_test=lambda v: isinstance(v, str) and UUID_RE.fullmatch(v),
                               avoid=("conversation",)) or None
                if not cid:
                    m = UUID_RE.search(body)
                    cid = m.group(0) if m else None
                if cid:
                    if self.verbose:
                        eprint(f"    [conversation created via POST {path}]")
                    return cid, "POST " + path
        # Fallback: the API accepts a client-generated conversation id.
        return str(uuidlib.uuid4()), "client-generated uuid"

    def post_message(self, conversation_id, prompt):
        def _post(cid):
            return self.request("POST", "/api/companion/messages",
                                json_body={"conversationId": cid, "prompt": prompt})

        status, _, body = _post(conversation_id)
        if status in (400, 404, 409, 422) and conversation_id:
            # The id we invented may not exist server-side: ask the API to open one.
            status2, _, body2 = _post(None)
            if status2 < 300:
                status, body = status2, body2
        if status >= 400:
            raise ApiError(f"POST /api/companion/messages -> {status}: {body[:400]}",
                           status, body)
        data = parse_json(body) or {}
        mid = find_key(data, ID_KEYS,
                       value_test=lambda v: isinstance(v, str) and UUID_RE.fullmatch(v),
                       avoid=("conversation", "parent", "thread"))
        if not mid:
            # some APIs return the id outside the JSON body (Location header)
            m = UUID_RE.search(body)
            mid = m.group(0) if m else None
        if not mid:
            raise ApiError(f"created a message but found no id in response: {body[:400]}")
        new_conv = find_key(data, ("conversationId", "conversation_id"),
                            value_test=lambda v: isinstance(v, str) and UUID_RE.fullmatch(v))
        return mid, new_conv or conversation_id, body

    def stream_chat(self, message_id, timeout=300):
        """POST /api/companion/messages/{id}/chat -> yields SSE events."""
        self.refresh_token()
        hdrs = self._headers({"accept": "text/event-stream"},
                             accept="text/event-stream",
                             ctype="application/x-www-form-urlencoded")
        hdrs["content-length"] = "0"
        url = f"{self.cfg.base}/api/companion/messages/{message_id}/chat"
        req = urllib.request.Request(url, data=b"", headers=hdrs, method="POST")
        if self.verbose:
            eprint(f"    > POST /api/companion/messages/{message_id}/chat (SSE)")
        try:
            resp = urllib.request.urlopen(req, timeout=timeout, context=self._ctx)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace") if exc.fp else ""
            raise ApiError(f"chat stream -> {exc.code}: {body[:400]}", exc.code, body)
        except urllib.error.URLError as exc:
            raise ApiError(f"chat stream request failed: {exc.reason}") from exc
        ctype = resp.headers.get("content-type", "")
        if "text/event-stream" not in ctype:
            body = resp.read().decode("utf-8", "replace")
            resp.close()
            if "text/html" in ctype:
                raise ApiError("chat stream returned HTML -- cookies/session rejected",
                               None, body[:400])
            # Not SSE: maybe the whole answer came back as JSON.
            yield ("json", body)
            return
        yield from iter_sse(resp)


# --------------------------------------------------------------------------- #
# SSE + payload shape handling
# --------------------------------------------------------------------------- #
def iter_sse(resp):
    """Yield (event, data) tuples from a live SSE response object."""
    event, data = None, []
    while True:
        raw = resp.readline()
        if not raw:
            break
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if line == "":
            if data:
                yield (event or "message", "\n".join(data))
            event, data = None, []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip())
        elif line.startswith(("id:", "retry:")):
            continue
        else:
            data.append(line)
    if data:
        yield (event or "message", "\n".join(data))


def dig(obj, dotted):
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def extract_text(obj, path=None):
    """Best-effort pull of the assistant's text out of an unknown event payload."""
    if obj is None:
        return None
    if isinstance(obj, str):
        return None if obj == "[DONE]" else obj
    if path:
        found = dig(obj, path)
        if isinstance(found, str):
            return found
        if found is not None:
            return None
    if isinstance(obj, list):
        for item in obj:
            got = extract_text(item)
            if got:
                return got
        return None
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("error"), str):
        return "\x00error:" + obj["error"]
    for key in ("choices",):  # OpenAI-ish
        val = obj.get(key)
        if isinstance(val, list) and val:
            for sub in ("delta", "message"):
                if isinstance(val[0], dict) and isinstance(val[0].get(sub), dict):
                    got = extract_text(val[0][sub])
                    if got:
                        return got
            got = extract_text(val[0])
            if got:
                return got
    for key in ("delta", "data", "message", "result", "payload", "answer"):
        if key in obj and isinstance(obj[key], (dict, list)):
            got = extract_text(obj[key])
            if got:
                return got
    for key in CONTENT_KEYS:
        if isinstance(obj.get(key), str):
            return obj[key]
    return None


def is_done(event, data, obj):
    if data.strip() == "[DONE]":
        return True
    name = (event or "").lower()
    if name in ("done", "end", "finish", "finished", "stop", "complete", "completed"):
        return True
    if isinstance(obj, dict):
        for key in ("type", "event", "status", "state"):
            if isinstance(obj.get(key), str) and obj[key].lower() in (
                    "done", "end", "finish", "finished", "stop", "completed"):
                return True
    return False


# --------------------------------------------------------------------------- #
# one chat turn
# --------------------------------------------------------------------------- #
class Turn:
    """Runs prompt -> message -> SSE, printing the streamed answer."""

    def __init__(self, api, cfg, *, dump=None, verbose=False, quiet=False):
        self.api = api
        self.cfg = cfg
        self.dump = dump
        self.verbose = verbose
        self.quiet = quiet
        self.raw_events = []

    def run(self, conversation_id, prompt):
        mid, cid, _ = self.api.post_message(conversation_id, prompt)
        if self.verbose:
            eprint(f"    [message id {mid}]")
        text, done_seen, err = self._stream(mid)
        if not text and not err:
            # Stream produced nothing recognisable: try the message resource.
            try:
                status, _, body = self.api.get_message(mid)
                if status < 300:
                    got = extract_text(parse_json(body), self.cfg.sse_path)
                    if got and not got.startswith("\x00error:"):
                        if not self.quiet:
                            sys.stdout.write(got)
                            sys.stdout.flush()
                        text = got
            except ApiError:
                pass
        return {"message_id": mid, "conversation_id": cid, "text": text,
                "done": done_seen, "error": err, "events": self.raw_events}

    def _stream(self, mid):
        fh = open(self.dump, "a", encoding="utf-8") if self.dump else None
        out, done_seen, err = [], False, None
        try:
            for event, data in self.api.stream_chat(mid):
                if fh:
                    fh.write(f"event: {event}\ndata: {data}\n\n")
                    fh.flush()
                self.raw_events.append((event, data))
                if data.strip() == "[DONE]":
                    done_seen = True
                    continue
                obj = parse_json(data)
                if obj is None and event != "json":
                    # plain-text chunk
                    if data.strip():
                        sys.stdout.write(data)
                        sys.stdout.flush()
                        out.append(data)
                    continue
                if is_done(event, data, obj):
                    done_seen = True
                    if event == "json":
                        got = extract_text(obj, self.cfg.sse_path)
                        if got:
                            sys.stdout.write(got)
                            sys.stdout.flush()
                            out.append(got)
                    continue
                got = extract_text(obj, self.cfg.sse_path)
                if got is None:
                    if self.verbose:
                        eprint(f"    [skipped {event}: {data[:160]}]")
                    continue
                if got.startswith("\x00error:"):
                    err = got[len("\x00error:"):]
                    eprint(f"\n[server error] {err}")
                    continue
                sys.stdout.write(got)
                sys.stdout.flush()
                out.append(got)
        except ApiError as exc:
            err = str(exc)
            eprint(f"\n[stream error] {exc}")
        finally:
            if fh:
                fh.close()
        if out and not "".join(out).endswith("\n"):
            sys.stdout.write("\n")
            sys.stdout.flush()
        elif not out and not err:
            eprint("[no text found in the stream]")
            for ev, dt in self.raw_events[:3]:
                eprint(f"    raw event {ev!r}: {dt[:200]}")
            eprint("    -> rerun with -v to see every event, then pin the field with "
                   "--sse-path <dotted.path>  (e.g. delta.content)")
        return "".join(out), done_seen, err


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_probe(api, cfg):
    print(f"base url   : {cfg.base}")
    print(f"cookies    : {len(api.cookies)} ({', '.join(sorted(api.cookies)) or 'none'})")
    try:
        tok = api.refresh_token(force=True)
        claims = jwt_claims(tok)
        exp = claims.get("exp")
        print(f"token      : OK ({len(tok)} chars, sub={claims.get('preferred_username')}, "
              f"expires in {int(exp - time.time()) if exp else '?'}s)")
    except ApiError as exc:
        print(f"token      : FAIL -- {exc}")
        return 1
    try:
        status, _, body = api.whoami()
        print(f"{'GET /api/account/me':46s} -> {status}")
        print("   " + body[:300].replace("\n", " "))
    except ApiError as exc:
        print(f"{'GET /api/account/me':46s} -> FAIL {exc}")
    try:
        items, body = api.list_conversations(3)
        print(f"{'GET /api/companion/conversations?limit=3':46s} -> OK "
              f"({len(items)} parsed)")
        render_conversations(items, 3)
        if not items:
            print("   raw: " + body[:300].replace("\n", " "))
    except ApiError as exc:
        print(f"{'GET /api/companion/conversations?limit=3':46s} -> FAIL {exc}")
    try:
        cid, how = api.create_conversation()
        print(f"{'POST /api/companion/conversations':46s} -> OK ({how}) {cid}")
    except ApiError as exc:
        print(f"{'POST /api/companion/conversations':46s} -> FAIL {exc}")
    return 0


def cmd_import_curl(args):
    text = (open(args.file, encoding="utf-8", errors="replace").read()
            if args.file and args.file != "-" else sys.stdin.read())
    cookies, token, referer = load_curl_text(text)
    if not cookies and not token:
        eprint("no cookies and no bearer token found in that curl blob")
        return 1
    cfg = Config.load()
    if cookies:
        cfg.cookies = "; ".join(f"{k}={v}" for k, v in cookies.items())
    if token:
        cfg.token = token
    if referer and "/conversations/" in referer:
        cfg.referer = referer
        m = UUID_RE.search(referer)
        if m:
            cfg.conversation = m.group(0)
    cfg.save()
    print(f"imported {len(cookies)} cookies"
          + (", bearer token" if token else "")
          + (f", conversation {cfg.conversation}" if cfg.conversation else ""))
    return 0


def render_conversations(items, limit=15):
    rows = []
    for it in items[:limit]:
        if not isinstance(it, dict):
            continue
        cid = find_key(it, ID_KEYS, value_test=lambda v: isinstance(v, str))
        title = find_key(it, TITLE_KEYS, value_test=lambda v: isinstance(v, str)) or ""
        when = ""
        for k in ("createdAt", "updatedAt", "created_at", "updated_at", "lastMessageAt"):
            if isinstance(it.get(k), (str, int)):
                when = str(it[k])[:19]
                break
        rows.append((str(cid), title.replace("\n", " ")[:70], when))
    for i, (cid, title, when) in enumerate(rows, 1):
        print(f"  {i:2d}  {cid}  {when:20s}  {title}")
    return rows


# --------------------------------------------------------------------------- #
# REPL
# --------------------------------------------------------------------------- #
HELP = """\
type text            -> send it to the AI (streamed answer)
\\ at end of line     -> continue on the next line
/ml                  -> multiline mode, finish with a line containing only '.'
/new                 -> start a fresh conversation
/list [n]            -> list recent conversations
/use <n|uuid>        -> switch to a conversation from /list (or a raw uuid)
/conv                -> show the current conversation id
/token               -> force a token refresh
/retry               -> resend the last prompt
/copy                -> reprint the last answer (no streaming)
/dump [file]         -> write raw SSE events to a file (default ./sse-dump.txt)
/v                   -> toggle verbose (shows every raw event)
/save                -> persist cookies/token/conversation to the config file
/help                -> this text
/quit                -> exit (also Ctrl-D)
"""


def read_prompt(multiline):
    lines = []
    while True:
        try:
            line = input("you> " if not lines else "...> ")
        except EOFError:
            raise
        if multiline:
            if line.strip() == ".":
                return "\n".join(lines)
            if not lines and line.strip().startswith("/"):
                return line          # commands still work in multiline mode
            lines.append(line)
            continue
        if line.endswith("\\"):
            lines.append(line[:-1])
            continue
        lines.append(line)
        return "\n".join(lines)


def repl(api, cfg, args):
    state = {"multiline": False, "verbose": args.verbose,
             "dump": args.dump, "last_prompt": None, "last_answer": ""}
    conv_rows = []
    if cfg.conversation:
        print(f"conversation {cfg.conversation}")
    else:
        cid, how = api.create_conversation()
        cfg.conversation = cid
        print(f"new conversation {cid}  ({how})")
    print("MyCompanion terminal client -- /help for commands\n")

    while True:
        try:
            text = read_prompt(state["multiline"])
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print("^C")
            continue
        text = text.strip()
        if not text:
            continue

        if text.startswith("/"):
            parts = text.split()
            cmd, rest = parts[0].lower(), parts[1:]
            if cmd in ("/quit", "/exit", "/q"):
                break
            elif cmd == "/help":
                print(HELP)
            elif cmd == "/ml":
                state["multiline"] = not state["multiline"]
                print("multiline on (end with '.')" if state["multiline"] else "multiline off")
            elif cmd == "/v":
                state["verbose"] = not state["verbose"]
                api.verbose = state["verbose"]
                print(f"verbose {'on' if state['verbose'] else 'off'}")
            elif cmd == "/dump":
                state["dump"] = rest[0] if rest else (state["dump"] or "sse-dump.txt")
                print(f"raw SSE -> {state['dump']}")
            elif cmd == "/new":
                cid, how = api.create_conversation()
                cfg.conversation = cid
                print(f"new conversation {cid} ({how})")
            elif cmd == "/conv":
                print(cfg.conversation or "(none)")
            elif cmd == "/list":
                n = int(rest[0]) if rest and rest[0].isdigit() else 15
                try:
                    items, _ = api.list_conversations(n)
                    conv_rows = render_conversations(items, n)
                    if not conv_rows:
                        print("  (no conversations parsed -- try -v and check the raw body)")
                except ApiError as exc:
                    print(f"error: {exc}")
            elif cmd == "/use":
                if not rest:
                    print("usage: /use <n|uuid>")
                elif rest[0].isdigit() and int(rest[0]) - 1 < len(conv_rows):
                    cfg.conversation = conv_rows[int(rest[0]) - 1][0]
                    print(f"conversation {cfg.conversation}")
                elif UUID_RE.fullmatch(rest[0]):
                    cfg.conversation = rest[0]
                    print(f"conversation {cfg.conversation}")
                else:
                    print("give a number from /list or a uuid")
            elif cmd == "/token":
                try:
                    api.refresh_token(force=True)
                    exp = api.token_exp or 0
                    print(f"token refreshed, {int(exp - time.time())}s left")
                except ApiError as exc:
                    print(f"error: {exc}")
            elif cmd == "/retry":
                if state["last_prompt"]:
                    text = state["last_prompt"]
                else:
                    print("nothing to retry")
                    continue
            elif cmd == "/copy":
                print(state["last_answer"] or "(no answer yet)")
            elif cmd == "/save":
                cfg.conversation = cfg.conversation
                cfg.save()
            else:
                print(f"unknown command {cmd} -- /help")
            continue

        state["last_prompt"] = text
        try:
            turn = Turn(api, cfg, dump=state["dump"], verbose=state["verbose"])
            res = turn.run(cfg.conversation, text)
            cfg.conversation = res["conversation_id"]
            state["last_answer"] = res["text"] or ""
            if res["error"] and not state["last_answer"]:
                print(f"(turn failed: {res['error']})")
        except ApiError as exc:
            eprint(f"[error] {exc}")
            if "cookie" in str(exc) or "HTML" in str(exc):
                eprint("  -> re-login in the browser, copy the request as cURL, then run:")
                eprint("     ./companion.py import-curl the-curl-file")
    if args.save:
        cfg.save()


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def build_config(args):
    cfg = Config.load()
    if args.base_url:
        cfg.base = args.base_url.rstrip("/")
        cfg.referer = cfg.base + "/"
    if args.cookies:
        cfg.cookies = args.cookies
    if args.cookies_file:
        cfg.cookies = open(args.cookies_file, encoding="utf-8").read()
    if args.curl_file:
        text = open(args.curl_file, encoding="utf-8", errors="replace").read()
        cookies, token, referer = load_curl_text(text)
        if cookies:
            cfg.cookies = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if token and not args.no_token:
            cfg.token = token
        if referer:
            cfg.referer = referer
    if args.token:
        cfg.token = args.token
    if args.no_token:
        cfg.token = ""
    if args.conversation:
        cfg.conversation = args.conversation
    if args.new:
        cfg.conversation = None
    if args.sse_path:
        cfg.sse_path = args.sse_path
    if args.insecure:
        cfg.insecure = True
    if not cfg.referer or cfg.referer == DEFAULT_BASE + "/":
        cfg.referer = cfg.base + "/serviceWorker.js"
    return cfg


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Terminal client for the MyCompanion chat API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:")[-1])
    p.add_argument("command", nargs="?", default="chat",
                   choices=["chat", "ask", "probe", "import-curl"],
                   help="chat (default REPL), ask <text>, probe, import-curl <file>")
    p.add_argument("rest", nargs="*", help="argument for the command")
    p.add_argument("--base-url", help=f"API base (default {DEFAULT_BASE})")
    p.add_argument("--cookies", help="full Cookie header string from the browser")
    p.add_argument("--cookies-file", help="read the cookie string from a file")
    p.add_argument("--curl-file", help="'Copy as cURL' file to harvest cookies/token from")
    p.add_argument("--token", help="bearer token (otherwise minted from cookies)")
    p.add_argument("--no-token", action="store_true",
                   help="ignore any saved bearer token (always mint a fresh one)")
    p.add_argument("--conversation", "--cid", dest="conversation",
                   help="existing conversation id (default: create a new one)")
    p.add_argument("--new", action="store_true",
                   help="ignore the saved conversation and open a fresh one")
    p.add_argument("--sse-path", help="dotted path of the answer text inside SSE JSON "
                                      "events, e.g. delta.content")
    p.add_argument("--dump", metavar="FILE", help="append raw SSE events to FILE")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--save", action="store_true", help="persist config on exit")
    p.add_argument("--timeout", type=int, default=300, help="stream timeout (s)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    if args.command == "import-curl":
        ns = argparse.ArgumentParser().parse_args([])
        ns.file = args.rest[0] if args.rest else "-"
        return cmd_import_curl(ns)

    cfg = build_config(args)
    if not cfg.cookies and not cfg.token:
        eprint("No credentials.\n"
               "  1. log in in the browser\n"
               "  2. devtools > Network > any /api/... request > right click > Copy as cURL\n"
               "  3. save it to a file and run:  ./companion.py import-curl that-file\n"
               "     (or pass --cookies 'a=1; b=2' / --curl-file that-file)")
        return 2

    api = Api(cfg, verbose=args.verbose)
    try:
        if args.command == "probe":
            return cmd_probe(api, cfg)
        if args.command == "ask":
            if not args.rest:
                eprint("usage: companion.py ask \"your question\"")
                return 2
            prompt = " ".join(args.rest)
            cid = cfg.conversation
            if not cid:
                cid, _ = api.create_conversation()
            turn = Turn(api, cfg, dump=args.dump, verbose=args.verbose,
                        quiet=not sys.stdout.isatty())
            res = turn.run(cid, prompt)
            if not sys.stdout.isatty() and res["text"]:
                pass  # already streamed to stdout
            if res["error"] and not res["text"]:
                eprint(f"error: {res['error']}")
                return 1
            return 0
        return repl(api, cfg, args)
    except ApiError as exc:
        eprint(f"error: {exc}")
        return 1
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    sys.exit(main())
