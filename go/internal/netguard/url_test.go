package netguard

import (
	"errors"
	"strings"
	"testing"
)

func newTestGuard(t testing.TB, opts ...Option) *Guard {
	t.Helper()
	g, err := NewGuard(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestCheckURL_Table(t *testing.T) {
	type tc struct {
		name   string
		url    string
		reason Reason // "" = accepted
	}
	long := "https://example.com/" + strings.Repeat("a", MaxURLLength)
	cases := []tc{
		// accepted
		{"plain https", "https://example.com/", ""},
		{"upper-case scheme and host", "HTTPS://EXAMPLE.COM/x", ""},
		{"port", "https://example.com:8443/p?q=1#f", ""},
		{"trailing dot", "https://example.com./", ""},
		{"punycode IDN", "https://xn--bcher-kva.example/", ""},
		{"public v4 literal", "https://93.184.216.34/", ""},
		{"public v6 literal", "https://[2606:4700:4700::1111]:443/", ""},
		{"underscore label", "https://_dmarc.example.com/", ""},
		{"max port", "https://example.com:65535/", ""},
		{"empty port", "https://example.com:/", ""},

		// scheme
		{"http without opt-in", "http://example.com/", ReasonScheme},
		{"ftp", "ftp://example.com/", ReasonScheme},
		{"file", "file:///etc/passwd", ReasonScheme},
		{"gopher", "gopher://example.com/", ReasonScheme},
		{"javascript", "javascript:alert(1)", ReasonScheme},
		{"data", "data:text/plain,hi", ReasonScheme},
		{"scheme-relative", "//example.com/", ReasonScheme},
		{"no scheme", "example.com", ReasonScheme},
		{"opaque", "https:example.com", ReasonURL},

		// shape
		{"empty", "", ReasonURL},
		{"too long", long, ReasonURL},
		{"space", "https://example.com/a b", ReasonURL},
		{"leading space", " https://example.com/", ReasonURL},
		{"tab", "https://example.com/\t", ReasonURL},
		{"CRLF", "https://example.com/\r\nHost: evil", ReasonURL},
		{"NUL", "https://example.com\x00.evil/", ReasonURL},
		{"DEL", "https://example.com/\x7f", ReasonURL},
		{"non-ascii path", "https://example.com/é", ReasonURL},
		{"missing host", "https:///path", ReasonHost},
		{"missing host port only", "https://:443/", ReasonHost},

		// userinfo tricks
		{"user:pass", "https://user:pass@example.com/", ReasonUserinfo},
		{"user only", "https://user@example.com/", ReasonUserinfo},
		{"empty userinfo", "https://@example.com/", ReasonUserinfo},
		{"colon userinfo", "https://:@example.com/", ReasonUserinfo},
		{"host as userinfo", "https://example.com@evil.example/", ReasonUserinfo},
		{"double at", "https://a@b@example.com/", ReasonUserinfo},
		{"backslash userinfo", "https://evil.example\\@example.com/", ReasonURL},
		{"fragment trick (host is evil.example, nothing to exploit)", "https://evil.example#@example.com/", ""},

		// IDN / unicode
		{"unicode host", "https://bücher.example/", ReasonURL},
		{"ideographic full stop", "https://example。com/", ReasonURL},
		{"fullwidth digits", "https://１２７.0.0.1/", ReasonURL},

		// legacy / ambiguous IPv4 spellings
		{"decimal", "https://2130706433/", ReasonHost},
		{"hex", "https://0x7f000001/", ReasonHost},
		{"octal", "https://0177.0.0.1/", ReasonHost},
		{"octal long", "https://017700000001/", ReasonHost},
		{"short", "https://127.1/", ReasonHost},
		{"short3", "https://127.0.1/", ReasonHost},
		{"hex dotted", "https://0x7f.0.0.1/", ReasonHost},
		{"hex short", "https://0x7f.1/", ReasonHost},
		{"too many parts", "https://1.1.1.1.1/", ReasonHost},
		{"leading zero octet", "https://08.0.0.1/", ReasonHost},
		{"public as decimal", "https://134744072/", ReasonHost},

		// IP literals in forbidden ranges
		{"loopback", "https://127.0.0.1/", ReasonAddress},
		{"loopback v6", "https://[::1]/", ReasonAddress},
		{"unspecified", "https://0.0.0.0/", ReasonAddress},
		{"metadata", "https://169.254.169.254/latest/meta-data/", ReasonAddress},
		{"rfc1918", "https://10.0.0.1/", ReasonAddress},
		{"cgnat", "https://100.64.0.1/", ReasonAddress},
		{"ula", "https://[fd00::1]/", ReasonAddress},
		{"link-local v6", "https://[fe80::1]/", ReasonAddress},
		{"mapped loopback", "https://[::ffff:127.0.0.1]/", ReasonAddress},
		{"mapped metadata", "https://[::ffff:169.254.169.254]/", ReasonAddress},
		{"mapped hex", "https://[::ffff:7f00:1]/", ReasonAddress},
		{"nat64", "https://[64:ff9b::7f00:1]/", ReasonAddress},
		{"v6 zero-compressed loopback", "https://[0:0:0:0:0:0:0:1]/", ReasonAddress},

		// zones and percent-encoding
		{"zone encoded", "https://[fe80::1%25eth0]/", ReasonHost},
		{"zone raw", "https://[fe80::1%eth0]/", ReasonURL},
		{"zone on global", "https://[2606:4700:4700::1111%25eth0]/", ReasonHost},
		{"pct host", "https://example%2ecom/", ReasonURL},
		{"pct digits", "https://%31%32%37.0.0.1/", ReasonURL},

		// ports
		{"port 0", "https://example.com:0/", ReasonPort},
		{"port 65536", "https://example.com:65536/", ReasonPort},
		{"port non-numeric", "https://example.com:abc/", ReasonURL},
		{"port negative", "https://example.com:-1/", ReasonURL},
		{"two ports", "https://example.com:80:80/", ReasonURL},

		// hostname syntax
		{"empty label", "https://example..com/", ReasonHost},
		{"leading dot", "https://.example.com/", ReasonHost},
		{"two trailing dots", "https://example.com../", ReasonHost},
		{"bang", "https://exam!ple.com/", ReasonHost},
		{"long label", "https://" + strings.Repeat("a", 64) + ".example/", ReasonHost},
		{"long host", "https://" + strings.Repeat("a.", 130) + "example/", ReasonHost},
	}
	g := newTestGuard(t)
	for _, c := range cases {
		u, err := g.CheckURL(c.url)
		if c.reason == "" {
			if err != nil {
				t.Errorf("%s: %q refused: %v", c.name, c.url, err)
			} else if strings.HasPrefix(c.name, "fragment trick") && u.Hostname() != "evil.example" {
				t.Errorf("%s: host=%q", c.name, u.Hostname())
			}
			continue
		}
		var be *BlockedError
		switch {
		case err == nil:
			t.Errorf("%s: %q accepted, want %s", c.name, c.url, c.reason)
		case !errors.As(err, &be) || !errors.Is(err, ErrBlocked):
			t.Errorf("%s: error is not a BlockedError: %v", c.name, err)
		case be.Reason != c.reason:
			t.Errorf("%s: %q reason=%s want %s (%v)", c.name, c.url, be.Reason, c.reason, err)
		}
	}
}

func TestCheckURL_AllowPrivateAndHTTP(t *testing.T) {
	g := newTestGuard(t, WithAllowPrivate(true), WithAllowInsecureHTTP(true))
	for _, u := range []string{"http://127.0.0.1:8080/", "http://[::1]/", "https://10.0.0.5/", "http://100.64.0.1/", "http://[fd00::1]/", "http://[::ffff:10.0.0.1]/"} {
		if _, err := g.CheckURL(u); err != nil {
			t.Errorf("%q refused with allowPrivate: %v", u, err)
		}
	}
	for _, u := range []string{"http://169.254.169.254/", "http://[fe80::1]/", "http://224.0.0.1/", "http://0.0.0.0/", "http://255.255.255.255/", "http://[::ffff:169.254.169.254]/", "http://[64:ff9b::a9fe:a9fe]/"} {
		if _, err := g.CheckURL(u); err == nil {
			t.Errorf("%q accepted even with allowPrivate (must stay blocked)", u)
		}
	}
	// ambiguous numeric hosts and userinfo stay refused regardless
	for _, u := range []string{"http://2130706433/", "http://user@127.0.0.1/"} {
		if _, err := g.CheckURL(u); err == nil {
			t.Errorf("%q accepted with allowPrivate", u)
		}
	}
}

func TestCheckURL_Allowlist(t *testing.T) {
	g := newTestGuard(t, WithAllowedHosts("api.example.com:443", "Docs.Example.com", "*.cdn.example.net", "[2606:4700:4700::1111]:8443", "bare.example:8080"))
	ok := []string{
		"https://api.example.com/x",
		"https://API.EXAMPLE.COM:443/x",
		"https://docs.example.com/x",
		"https://docs.example.com:9999/x", // host-only entry = any port
		"https://a.cdn.example.net/x",
		"https://a.b.cdn.example.net/x",
		"https://[2606:4700:4700::1111]:8443/",
		"https://bare.example:8080/",
	}
	bad := []string{
		"https://api.example.com:8443/x", // wrong port
		"https://evil.example.com/x",
		"https://cdn.example.net/x", // wildcard excludes the apex
		"https://evilcdn.example.net/x",
		"https://api.example.com.evil.example/x",
		"https://[2606:4700:4700::1111]/", // default port 443 != 8443
		"https://bare.example/",
	}
	for _, u := range ok {
		if _, err := g.CheckURL(u); err != nil {
			t.Errorf("allow-listed %q refused: %v", u, err)
		}
	}
	for _, u := range bad {
		_, err := g.CheckURL(u)
		var be *BlockedError
		if !errors.As(err, &be) || be.Reason != ReasonAllowlist {
			t.Errorf("%q: want allowlist refusal, got %v", u, err)
		}
	}
	// the allow-list never widens: a listed private literal is still refused
	g2 := newTestGuard(t, WithAllowedHosts("127.0.0.1:8443"))
	if _, err := g2.CheckURL("https://127.0.0.1:8443/"); err == nil {
		t.Error("allow-listed loopback accepted without allowPrivate")
	}
}

func TestParseAllowEntry_Errors(t *testing.T) {
	for _, bad := range []string{"", " ", "host:0", "host:70000", "host:abc", "::1", "[::1", "[::1]x", "[::1]:0", "*", "a/b", "user@host", "ho st", "*.:443"} {
		if _, err := NewGuard(WithAllowedHosts(bad)); err == nil {
			t.Errorf("allow-list entry %q accepted", bad)
		}
	}
	for _, good := range []string{"example.com", "example.com:443", "*.example.com", "[::1]", "[::1]:8080", "EXAMPLE.com."} {
		if _, err := NewGuard(WithAllowedHosts(good)); err != nil {
			t.Errorf("allow-list entry %q refused: %v", good, err)
		}
	}
}

func TestOptions_Validation(t *testing.T) {
	if _, err := NewGuard(WithMaxRedirects(-1)); err == nil {
		t.Error("negative redirects accepted")
	}
	if _, err := NewGuard(WithMaxRedirects(11)); err == nil {
		t.Error("11 redirects accepted")
	}
	if _, err := NewGuard(WithTimeout(0)); err == nil {
		t.Error("zero timeout accepted")
	}
	if _, err := NewGuard(WithResolver(nil)); err == nil {
		t.Error("nil resolver accepted")
	}
}
