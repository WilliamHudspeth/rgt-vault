package gateway

import (
	"net"
	"net/netip"
	"strings"
)

// DefaultListenAddr is the gateway's default bind address: loopback only.
const DefaultListenAddr = "127.0.0.1:8088"

// IsLoopbackAddr reports whether a listen address (host:port) binds only to a
// loopback interface. An empty host (":8088") means all interfaces and is not
// loopback; "localhost" is accepted.
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host) // accepts zones, e.g. ::1%lo
	return err == nil && ip.IsLoopback()
}
