package netguard

import (
	"errors"
	"net"
	"testing"
)

func TestCheckIP_Table(t *testing.T) {
	type tc struct {
		ip       string
		public   bool // allowed with allowPrivate=false
		priv     bool // allowed with allowPrivate=true
		wantName string
	}
	cases := []tc{
		// globally routable
		{"8.8.8.8", true, true, ""},
		{"1.1.1.1", true, true, ""},
		{"93.184.216.34", true, true, ""},
		{"172.15.255.255", true, true, ""},
		{"172.32.0.1", true, true, ""},
		{"2606:4700:4700::1111", true, true, ""},
		{"2a00:1450:4001::200e", true, true, ""},
		// loopback / RFC1918 / CGNAT / ULA etc.: lifted by allowPrivate
		{"127.0.0.1", false, true, "loopback"},
		{"127.255.255.254", false, true, "loopback"},
		{"::1", false, true, "loopback"},
		{"10.0.0.1", false, true, "RFC1918"},
		{"172.16.0.1", false, true, "RFC1918"},
		{"172.31.255.255", false, true, "RFC1918"},
		{"192.168.1.1", false, true, "RFC1918"},
		{"100.64.0.1", false, true, "CGNAT"},
		{"100.127.255.255", false, true, "CGNAT"},
		{"fc00::1", false, true, "ULA"},
		{"fd12:3456::1", false, true, "ULA"},
		{"fec0::1", false, true, "site-local"},
		{"192.0.0.8", false, true, "IETF"},
		{"192.0.2.1", false, true, "documentation"},
		{"198.18.0.1", false, true, "benchmark"},
		{"198.51.100.1", false, true, "documentation"},
		{"203.0.113.1", false, true, "documentation"},
		{"2001:db8::1", false, true, "documentation"},
		{"2001::1", false, true, "Teredo"},
		{"2002:7f00:1::", false, true, "6to4"},
		{"100::1", false, true, "discard"},
		{"64:ff9b:1::1", false, true, "NAT64"},
		// never allowed: link-local, metadata, multicast, unspecified, reserved
		{"169.254.169.254", false, false, "metadata"},
		{"169.254.0.1", false, false, "link-local"},
		{"fe80::1", false, false, "link-local"},
		{"fe80::a00:27ff:fe4e:66a1", false, false, "link-local"},
		{"0.0.0.0", false, false, "unspecified"},
		{"0.1.2.3", false, false, "unspecified"},
		{"::", false, false, "unspecified"},
		{"224.0.0.1", false, false, "multicast"},
		{"239.255.255.250", false, false, "multicast"},
		{"ff02::1", false, false, "multicast"},
		{"255.255.255.255", false, false, "reserved"},
		{"240.0.0.1", false, false, "reserved"},
		{"4000::1", false, false, "reserved"},
		{"::127.0.0.1", false, false, "reserved"}, // IPv4-compatible
		{"::ffff:0:7f00:1", false, false, "reserved"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test ip %q", c.ip)
		}
		errPub := CheckIP(ip, false)
		errPriv := CheckIP(ip, true)
		if (errPub == nil) != c.public {
			t.Errorf("%s allowPrivate=false: err=%v want allowed=%v", c.ip, errPub, c.public)
		}
		if (errPriv == nil) != c.priv {
			t.Errorf("%s allowPrivate=true: err=%v want allowed=%v", c.ip, errPriv, c.priv)
		}
		if errPub != nil && !errors.Is(errPub, ErrBlocked) {
			t.Errorf("%s: error does not match ErrBlocked: %v", c.ip, errPub)
		}
		_, hard, forbidden := ClassifyIP(ip)
		if forbidden == c.public {
			t.Errorf("%s: ClassifyIP forbidden=%v disagrees with CheckIP", c.ip, forbidden)
		}
		if forbidden && hard == c.priv {
			t.Errorf("%s: ClassifyIP hard=%v disagrees with allowPrivate result", c.ip, hard)
		}
	}
}

func TestCheckIP_MappedAndNAT64(t *testing.T) {
	// IPv4-mapped and NAT64 forms are refused unless allowPrivate; with it the
	// embedded IPv4 address is judged by the IPv4 rules.
	cases := []struct {
		lit       string
		pub, priv bool
		comment   string
	}{
		{"::ffff:127.0.0.1", false, true, "mapped loopback"},
		{"::ffff:10.0.0.1", false, true, "mapped RFC1918"},
		{"::ffff:169.254.169.254", false, false, "mapped metadata is never allowed"},
		{"::ffff:8.8.8.8", false, true, "mapped public: refused by default, parity with Python"},
		{"64:ff9b::7f00:1", false, true, "NAT64 loopback"},
		{"64:ff9b::a9fe:a9fe", false, false, "NAT64 metadata 169.254.169.254"},
		{"64:ff9b::808:808", false, true, "NAT64 public"},
	}
	for _, c := range cases {
		a := mustAddr(t, c.lit)
		if err := checkAddr(a, false, ""); (err == nil) != c.pub {
			t.Errorf("%s (%s) allowPrivate=false: err=%v", c.lit, c.comment, err)
		}
		if err := checkAddr(a, true, ""); (err == nil) != c.priv {
			t.Errorf("%s (%s) allowPrivate=true: err=%v", c.lit, c.comment, err)
		}
	}
	// A 16-byte net.IP holding a plain IPv4 address is judged as IPv4.
	if err := CheckIP(net.ParseIP("8.8.8.8"), false); err != nil {
		t.Errorf("16-byte form of 8.8.8.8 must be public: %v", err)
	}
	if err := CheckIP(net.ParseIP("10.1.2.3"), false); err == nil {
		t.Error("16-byte form of 10.1.2.3 must be blocked")
	}
	if err := CheckIP(nil, true); err == nil {
		t.Error("nil IP must be refused")
	}
	if _, _, forbidden := ClassifyIP(net.IP{1, 2, 3}); !forbidden {
		t.Error("malformed IP must be forbidden")
	}
	if _, hard, forbidden := ClassifyIP(net.ParseIP("::ffff:127.0.0.1")); !forbidden || hard {
		// net.IP cannot tell a mapped literal from IPv4, so it is judged as 127.0.0.1.
		t.Errorf("mapped loopback via net.IP: hard=%v forbidden=%v", hard, forbidden)
	}
}

func TestCheckAddr_ZoneRefused(t *testing.T) {
	a := mustAddr(t, "fe80::1").WithZone("eth0")
	if err := checkAddr(a, true, "h"); err == nil {
		t.Fatal("zoned address must be refused")
	}
	b := mustAddr(t, "2606:4700:4700::1111").WithZone("eth0")
	if err := checkAddr(b, false, "h"); err == nil {
		t.Fatal("zoned global address must be refused")
	}
}

func TestBlockedError_Text(t *testing.T) {
	e := blocked(ReasonAddress, "example.com", "nope")
	if e.Error() == "" || !errors.Is(e, ErrBlocked) {
		t.Fatal("blocked error text / Is")
	}
	e2 := blocked(ReasonURL, "", "bad")
	if want := "netguard: refusing url: bad"; e2.Error() != want {
		t.Fatalf("got %q want %q", e2.Error(), want)
	}
	if errors.Is(e, errors.New("other")) {
		t.Fatal("must not match unrelated errors")
	}
}
