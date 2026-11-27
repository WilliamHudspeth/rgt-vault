#!/usr/bin/env python3
"""Generate Python-parity vectors for go/internal/actions from the REAL Python
python/server/actions.py (RGT-156 / G8b).

Run from the repository root with the project venv:

    python3 -m venv .venv && .venv/bin/pip install -e '.[server,dev]'
    .venv/bin/python go/internal/actions/testdata/gen_vectors.py \
        > go/internal/actions/testdata/vectors.json

DNS is faked (FAKE_DNS) so the output is deterministic and offline. IP
literals and the legacy numeric IPv4 forms are resolved by the real
getaddrinfo (AI_NUMERICHOST), exactly as urllib would.

Two verdicts are recorded per URL vector:
  validation  _validate_outbound_url accepted the URL
  e2e         ...and a connection could actually be attempted (port parses,
              the host resolves). Go's single resolve-then-dial step is only
              comparable to this.
"""
import json
import socket
import sys
import urllib.parse
from unittest import mock

from rgt_vault.exceptions import ActionExecutionError
from rgt_vault.server import actions as A

FAKE_DNS = {
    "public.example": ["93.184.216.34"],
    "api.example.com": ["93.184.216.34"],
    "public6.example": ["2606:4700:4700::1111"],
    "internal.example": ["10.0.0.5"],
    "loopback.example": ["127.0.0.1"],
    "127.0.0.1.nip.io": ["127.0.0.1"],
    "mixed.example": ["93.184.216.34", "10.0.0.5"],
    "meta.example": ["169.254.169.254"],
    "cgnat.example": ["100.64.0.1"],
    "ula.example": ["fd00::1"],
    "mapped.example": ["::ffff:10.0.0.1"],
    "localhost": ["127.0.0.1", "::1"],
    "bücher.example": ["93.184.216.34"],
    "xn--bcher-kva.example": ["93.184.216.34"],
}


def fake_getaddrinfo(host, port, *a, **kw):
    try:
        return real_getaddrinfo(host, port, flags=socket.AI_NUMERICHOST, type=socket.SOCK_STREAM)
    except socket.gaierror:
        pass
    key = host.lower().rstrip(".") if isinstance(host, str) else host
    if key in FAKE_DNS:
        out = []
        for ip in FAKE_DNS[key]:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            sa = (ip, port or 0, 0, 0) if fam == socket.AF_INET6 else (ip, port or 0)
            out.append((fam, socket.SOCK_STREAM, 6, "", sa))
        return out
    raise socket.gaierror(-2, "Name or service not known")


real_getaddrinfo = socket.getaddrinfo


def url_vectors():
    u = [
        # --- ordinary
        "https://public.example/", "http://public.example/", "https://public.example:8443/p?q=1",
        "HTTPS://PUBLIC.EXAMPLE/", "https://public.example./", "https://public.example//a//b",
        "https://public.example/%2e%2e/x", "https://public.example/a?b=c#frag", "https://api.example.com/v1/x",
        "https://public6.example/", "https://[2606:4700:4700::1111]/", "https://8.8.8.8/", "https://1.1.1.1:443/",
        "https://93.184.216.34/",
        # --- schemes / shape
        "ftp://public.example/", "file:///etc/passwd", "gopher://public.example/", "javascript:alert(1)",
        "data:text/plain,hi", "//public.example/", "public.example", "", "   ", "http:///", "https://", "https://:443/",
        "http:public.example", "https:/public.example", "https:public.example",
        "ws://public.example/", "wss://public.example/",
        # --- loopback / private / special IPv4
        "http://127.0.0.1/", "http://127.0.0.1:8080/", "http://127.255.255.254/", "http://0.0.0.0/",
        "http://0.1.2.3/", "http://169.254.169.254/latest/meta-data/", "http://169.254.0.1/", "http://10.0.0.1/",
        "http://172.16.0.1/", "http://172.31.255.255/", "http://172.32.0.1/", "http://192.168.1.1/", "http://100.64.0.1/",
        "http://100.127.255.255/", "http://224.0.0.1/", "http://255.255.255.255/", "http://240.0.0.1/",
        "http://198.18.0.1/", "http://192.0.2.1/", "http://198.51.100.7/", "http://203.0.113.9/", "http://192.0.0.8/",
        # --- IPv6 specials
        "http://[::1]/", "http://[::]/", "http://[fe80::1]/", "http://[fd00::1]/", "http://[fc00::1]/",
        "http://[fec0::1]/", "http://[ff02::1]/", "http://[::ffff:127.0.0.1]/", "http://[::ffff:10.0.0.1]/",
        "http://[::ffff:169.254.169.254]/", "http://[::ffff:8.8.8.8]/", "http://[::ffff:7f00:1]/", "http://[::127.0.0.1]/",
        "http://[64:ff9b::7f00:1]/", "http://[64:ff9b::808:808]/", "http://[2002:7f00:1::]/", "http://[2001:db8::1]/",
        "http://[2001::1]/", "http://[100::1]/", "http://[4000::1]/", "http://[0:0:0:0:0:0:0:1]/",
        # --- legacy numeric IPv4 forms
        "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/", "http://127.1/", "http://0x7f.0.0.1/",
        "http://017700000001/", "http://127.0.1/", "http://0x7f.1/", "http://1.1.1.1.1/", "http://08.0.0.1/",
        "http://134744072/", "http://0x08080808/",
        # --- DNS names that resolve to special space (fake DNS)
        "https://localhost/", "https://LOCALHOST/", "https://localhost./", "https://internal.example/",
        "https://loopback.example/", "https://mixed.example/", "https://meta.example/", "https://cgnat.example/",
        "https://ula.example/", "https://mapped.example/", "https://127.0.0.1.nip.io/", "https://nx.example/",
        # --- ports
        "https://public.example:0/", "https://public.example:1/", "https://public.example:65535/",
        "https://public.example:65536/", "https://public.example:99999/", "https://public.example:abc/",
        "https://public.example:-1/", "https://public.example:/", "https://public.example:80:80/",
        "https://public.example:+443/", "https://public.example:0443/", "https://[2606:4700:4700::1111]:8443/",
        "https://127.0.0.1:65536/",
        # --- userinfo / authority tricks
        "https://user:pass@public.example/", "https://user@public.example/", "https://@public.example/",
        "https://public.example@internal.example/", "https://internal.example@public.example/",
        "https://user@10.0.0.1/", "https://a@b@public.example/", "https://public.example\\@internal.example/",
        "https://internal.example\\@public.example/", "https://internal.example#@public.example/",
        "https://public.example#.internal.example/", "https://public.example?@internal.example/",
        "https://public.example:443@internal.example/", "https://:@public.example/",
        # --- IDN / punycode / unicode
        "https://bücher.example/", "https://xn--bcher-kva.example/", "https://public。example/",
        "https://pub​lic.example/", "https://ｐｕｂｌｉｃ.example/", "https://１２７.0.0.1/",
        "https://xn--nxasmq6b.example/", "https://xn--/",
        # --- zones / percent
        "http://[fe80::1%25eth0]/", "http://[fe80::1%eth0]/", "http://[::1%25lo]/", "https://[2606:4700:4700::1111%25eth0]/",
        "https://public%2eexample/", "https://%31%32%37.0.0.1/", "https://public.example%00/", "https://pub%6Cic.example/",
        # --- control chars / whitespace
        "https://public.example/\r\nHost: evil", "https://pub\nlic.example/", "https://public.example/ path",
        "\thttps://public.example/", " https://public.example/", "https://public.example/\t", "https://public.example\x00.evil/",
        "https://public.example/\x7f", "https://public.example/é",
        # --- length
        "https://" + "a" * 63 + ".example/", "https://" + "a" * 64 + ".example/", "https://" + ("a." * 130) + "example/",
        "https://public.example/" + "a" * 2100, "https://public.example/" + "a" * 1900,
        # --- misc hosts
        "https://-public.example/", "https://public-.example/", "https://pub_lic.example/", "https://public..example/",
        "https://.public.example/", "https://public.example../", "https://pub lic.example/", "https://public.example!/",
    ]
    return u


def py_url(url, allow_private):
    rec = {"url": url, "allow_private": allow_private}
    try:
        with mock.patch("socket.getaddrinfo", fake_getaddrinfo):
            A._validate_outbound_url(url, allow_private_network=allow_private)
        rec["validation"] = "accept"
    except Exception as e:  # noqa: BLE001 - any failure is a reject
        rec["validation"] = "reject"
        rec["error_type"] = type(e).__name__
        rec["e2e"] = "reject"
        return rec
    # e2e: can a connection even be attempted?
    try:
        p = urllib.parse.urlparse(url)
        port = p.port or (443 if p.scheme.lower() == "https" else 80)
        with mock.patch("socket.getaddrinfo", fake_getaddrinfo):
            socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)
        rec["e2e"] = "accept"
    except Exception as e:  # noqa: BLE001
        rec["e2e"] = "reject"
        rec["e2e_error_type"] = type(e).__name__
    return rec


def header_vectors():
    big = "x" * 5000
    return [
        {"id": "empty", "h": {}},
        {"id": "plain", "h": {"X-Trace": "abc", "Accept": "application/json"}},
        {"id": "host-dropped", "h": {"Host": "evil.example", "X-A": "1"}},
        {"id": "host-lower", "h": {"host": "evil.example"}},
        {"id": "host-mixed", "h": {"HoSt": "evil.example"}},
        {"id": "int-value", "h": {"X-N": 5}},
        {"id": "float-value", "h": {"X-N": 1.5}},
        {"id": "bool-value", "h": {"X-B": True}},
        {"id": "null-value", "h": {"X-Z": None}},
        {"id": "list-value", "h": {"X-L": [1, 2]}},
        {"id": "obj-value", "h": {"X-O": {"a": 1}}},
        {"id": "crlf-value", "h": {"X-A": "ok\r\nInjected: 1"}},
        {"id": "lf-value", "h": {"X-A": "ok\nInjected: 1"}},
        {"id": "nul-value", "h": {"X-A": "ok\u0000"}},
        {"id": "crlf-name", "h": {"X-A\r\nInjected": "1"}},
        {"id": "space-name", "h": {"X A": "1"}},
        {"id": "colon-name", "h": {"X:A": "1"}},
        {"id": "empty-name", "h": {"": "1"}},
        {"id": "unicode-name", "h": {"Ｘ-A": "1"}},
        {"id": "unicode-value", "h": {"X-A": "héllo"}},
        {"id": "tab-value", "h": {"X-A": "a\tb"}},
        {"id": "ctl-value", "h": {"X-A": "a\x01b"}},
        {"id": "del-value", "h": {"X-A": "a\x7fb"}},
        {"id": "authorization", "h": {"Authorization": "Bearer attacker"}},
        {"id": "authorization-lower", "h": {"authorization": "Bearer attacker"}},
        {"id": "proxy-authorization", "h": {"Proxy-Authorization": "x"}},
        {"id": "content-length", "h": {"Content-Length": "5"}},
        {"id": "transfer-encoding", "h": {"Transfer-Encoding": "chunked"}},
        {"id": "connection", "h": {"Connection": "close"}},
        {"id": "upgrade", "h": {"Upgrade": "websocket"}},
        {"id": "te", "h": {"TE": "trailers"}},
        {"id": "expect", "h": {"Expect": "100-continue"}},
        {"id": "x-forwarded-for", "h": {"X-Forwarded-For": "1.2.3.4"}},
        {"id": "forwarded", "h": {"Forwarded": "for=1.2.3.4"}},
        {"id": "x-real-ip", "h": {"X-Real-IP": "1.2.3.4"}},
        {"id": "cookie", "h": {"Cookie": "a=b"}},
        {"id": "content-type", "h": {"Content-Type": "text/plain"}},
        {"id": "dup-case", "h": {"X-A": "1", "x-a": "2"}},
        {"id": "long-value", "h": {"X-A": big}},
        {"id": "long-name", "h": {"X" * 200: "1"}},
        {"id": "many", "h": {f"X-H{i}": "v" for i in range(40)}},
        {"id": "not-object-list", "h": [["a", "b"]]},
        {"id": "not-object-str", "h": "X-A: 1"},
        {"id": "not-object-null", "h": None},
        {"id": "not-object-int", "h": 3},
        {"id": "token-chars", "h": {"X-A_b.c~d`e|f": "1"}},
    ]


def py_headers(h):
    rec = {}
    try:
        rec["out"] = A._validate_headers(h)
        rec["verdict"] = "accept"
    except Exception as e:  # noqa: BLE001
        rec["verdict"] = "reject"
        rec["error_type"] = type(e).__name__
    return rec


class _Reached(Exception):
    pass


def action_vectors():
    msgs = [{"role": "user", "content": "hi"}]
    v = []

    def add(action, params, aid):
        v.append({"id": aid, "action": action, "params": params})

    add("openai_chat", {"model": "m", "messages": msgs}, "oa-minimal")
    add("openai_chat", {"model": "m", "messages": msgs, "max_tokens": 10, "temperature": 0.5}, "oa-full")
    add("openai_chat", {"model": "m", "messages": msgs, "max_tokens": 1_000_000}, "oa-max-tokens-edge")
    add("openai_chat", {"model": "m", "messages": msgs, "max_tokens": 1_000_001}, "oa-max-tokens-over")
    add("openai_chat", {"model": "m", "messages": msgs, "max_tokens": 0}, "oa-max-tokens-zero")
    add("openai_chat", {"model": "m", "messages": msgs, "max_tokens": -1}, "oa-max-tokens-neg")
    add("openai_chat", {"model": "m", "messages": msgs, "max_tokens": True}, "oa-max-tokens-bool")
    add("openai_chat", {"model": "m", "messages": msgs, "max_tokens": "5"}, "oa-max-tokens-str")
    add("openai_chat", {"model": "m", "messages": msgs, "max_tokens": 1.5}, "oa-max-tokens-frac")
    add("openai_chat", {"model": "m", "messages": msgs, "max_tokens": None}, "oa-max-tokens-null")
    add("openai_chat", {"model": "m", "messages": msgs, "temperature": 2}, "oa-temp-2")
    add("openai_chat", {"model": "m", "messages": msgs, "temperature": 2.01}, "oa-temp-over")
    add("openai_chat", {"model": "m", "messages": msgs, "temperature": -0.1}, "oa-temp-neg")
    add("openai_chat", {"model": "m", "messages": msgs, "temperature": True}, "oa-temp-bool")
    add("openai_chat", {"model": "m", "messages": msgs, "temperature": "1"}, "oa-temp-str")
    add("openai_chat", {"model": "", "messages": msgs}, "oa-model-empty")
    add("openai_chat", {"model": 5, "messages": msgs}, "oa-model-int")
    add("openai_chat", {"messages": msgs}, "oa-model-missing")
    add("openai_chat", {"model": "m"}, "oa-messages-missing")
    add("openai_chat", {"model": "m", "messages": []}, "oa-messages-empty")
    add("openai_chat", {"model": "m", "messages": "hi"}, "oa-messages-str")
    add("openai_chat", {"model": "m", "messages": ["hi"]}, "oa-message-str")
    add("openai_chat", {"model": "m", "messages": [{"content": "x"}]}, "oa-role-missing")
    add("openai_chat", {"model": "m", "messages": [{"role": "", "content": "x"}]}, "oa-role-empty")
    add("openai_chat", {"model": "m", "messages": [{"role": "user"}]}, "oa-content-missing")
    add("openai_chat", {"model": "m", "messages": [{"role": "user", "content": ""}]}, "oa-content-empty-str")
    add("openai_chat", {"model": "m", "messages": [{"role": "user", "content": [{"type": "text", "text": "x"}]}]}, "oa-content-list")
    add("openai_chat", {"model": "m", "messages": [{"role": "user", "content": 5}]}, "oa-content-int")
    add("openai_chat", {"model": "m", "messages": [{"role": "user", "content": "x", "name": "n"}]}, "oa-extra-key")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": "https://public.example"}, "oa-base-public")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": "https://public.example/"}, "oa-base-slash")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": "https://public.example/api"}, "oa-base-path")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": "https://public.example/api?x=1"}, "oa-base-query")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": "https://public.example/#f"}, "oa-base-frag")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": "http://public.example"}, "oa-base-http")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": "http://127.0.0.1:11434"}, "oa-base-loopback")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": "https://internal.example"}, "oa-base-internal")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": "https://u:p@public.example"}, "oa-base-userinfo")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": 5}, "oa-base-int")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": None}, "oa-base-null")
    add("openai_chat", {"model": "m", "messages": msgs, "base_url": ""}, "oa-base-empty")
    add("http_get_with_auth", {"url": "https://public.example/x"}, "get-basic")
    add("http_get_with_auth", {"url": "https://public.example/x", "headers": {"X-A": "1"}}, "get-headers")
    add("http_get_with_auth", {"url": "https://public.example/x", "headers": {"Host": "evil"}}, "get-host-header")
    add("http_get_with_auth", {"url": "https://public.example/x", "headers": {"X-A": "a\r\nb: c"}}, "get-crlf-header")
    add("http_get_with_auth", {"url": "https://public.example/x", "headers": {"Authorization": "Bearer evil"}}, "get-auth-header")
    add("http_get_with_auth", {"url": "https://public.example/x", "headers": "x"}, "get-headers-str")
    add("http_get_with_auth", {"url": "https://public.example/x", "headers": None}, "get-headers-null")
    add("http_get_with_auth", {"url": "https://public.example/x", "headers": {}}, "get-headers-empty")
    add("http_get_with_auth", {"url": ""}, "get-url-empty")
    add("http_get_with_auth", {}, "get-url-missing")
    add("http_get_with_auth", {"url": 5}, "get-url-int")
    add("http_get_with_auth", {"url": "http://127.0.0.1/"}, "get-loopback")
    add("http_get_with_auth", {"url": "http://169.254.169.254/latest/meta-data/"}, "get-metadata")
    add("http_get_with_auth", {"url": "https://internal.example/"}, "get-internal")
    add("http_get_with_auth", {"url": "ftp://public.example/"}, "get-ftp")
    add("http_post_with_auth", {"url": "https://public.example/x"}, "post-nobody")
    add("http_post_with_auth", {"url": "https://public.example/x", "body": {"a": 1}}, "post-json-body")
    add("http_post_with_auth", {"url": "https://public.example/x", "body": "raw text"}, "post-str-body")
    add("http_post_with_auth", {"url": "https://public.example/x", "body": ""}, "post-empty-str-body")
    add("http_post_with_auth", {"url": "https://public.example/x", "body": [1, 2]}, "post-list-body")
    add("http_post_with_auth", {"url": "https://public.example/x", "body": 5}, "post-int-body")
    add("http_post_with_auth", {"url": "https://public.example/x", "body": True}, "post-bool-body")
    add("http_post_with_auth", {"url": "https://public.example/x", "body": {"a": 1}, "headers": {"Content-Type": "text/plain"}}, "post-ct-upper")
    add("http_post_with_auth", {"url": "https://public.example/x", "body": {"a": 1}, "headers": {"content-type": "text/plain"}}, "post-ct-lower")
    add("http_post_with_auth", {"url": "https://public.example/x", "headers": {"Content-Type": "text/plain"}}, "post-ct-nobody")
    add("http_post_with_auth", {"url": "http://10.0.0.1/x", "body": "x"}, "post-private")
    add("echo", {}, "echo-empty")
    add("echo", {"message": "hello"}, "echo-msg")
    add("echo", {"message": 5}, "echo-msg-int")
    add("echo", {"message": None}, "echo-msg-null")
    add("echo", {"message": {"a": [1]}}, "echo-msg-obj")
    return v


def py_action(a, allow_private):
    reg = A.ActionRegistry()
    A.register_builtin_actions(reg)
    reg.default_allow_private_network = allow_private
    spec = reg.get(a["action"])
    rec = {"id": a["id"], "action": a["action"], "params": a["params"], "allow_private": allow_private}
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["method"] = req.get_method()
        captured["url"] = req.full_url
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        captured["data"] = None if req.data is None else req.data.decode("utf-8")
        raise _Reached()

    try:
        spec.validate_params(a["params"])
    except Exception as e:  # noqa: BLE001
        rec["verdict"] = "reject"
        rec["stage"] = "validate_params"
        rec["error_type"] = type(e).__name__
        return rec
    try:
        with mock.patch("socket.getaddrinfo", fake_getaddrinfo), mock.patch("urllib.request.urlopen", fake_urlopen):
            out = spec.fn(bytearray(b"SECRET-TOKEN"), a["params"], registry=reg)
        rec["verdict"] = "accept"
        rec["result"] = out
    except _Reached:
        rec["verdict"] = "accept"
        rec["request"] = captured
    except Exception as e:  # noqa: BLE001
        rec["verdict"] = "reject"
        rec["stage"] = "action"
        rec["error_type"] = type(e).__name__
        return rec
    # e2e: the resulting URL must be connectable (resolvable, valid port)
    if "request" in rec:
        try:
            p = urllib.parse.urlparse(captured["url"])
            port = p.port or (443 if p.scheme.lower() == "https" else 80)
            with mock.patch("socket.getaddrinfo", fake_getaddrinfo):
                socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)
        except Exception:  # noqa: BLE001
            rec["verdict"] = "reject"
            rec["stage"] = "e2e-dns"
    return rec


def main():
    urls = url_vectors()
    doc = {
        "python": sys.version.split()[0],
        "source": "python/server/actions.py",
        "fake_dns": FAKE_DNS,
        "urls": [],
        "headers": [],
        "actions": [],
    }
    for i, url in enumerate(urls):
        for ap in (False, True):
            r = py_url(url, ap)
            r["id"] = f"url-{i:03d}-{'priv' if ap else 'pub'}"
            doc["urls"].append(r)
    for hv in header_vectors():
        r = py_headers(hv["h"])
        r["id"] = hv["id"]
        r["headers"] = hv["h"]
        doc["headers"].append(r)
    for av in action_vectors():
        for ap in (False, True):
            r = py_action(av, ap)
            r["id"] = f"{av['id']}-{'priv' if ap else 'pub'}"
            doc["actions"].append(r)
    json.dump(doc, sys.stdout, indent=1, sort_keys=True, ensure_ascii=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
