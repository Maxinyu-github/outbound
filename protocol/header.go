package protocol

import (
	"crypto/tls"
	"time"
)

type Header struct {
	ProxyAddress string
	SNI          string
	Feature1     interface{}
	TlsConfig    *tls.Config
	Cipher       string
	User         string
	Password     string
	IsClient     bool
	Flags        Flags
	UtlsImitate           string // uTLS client hello fingerprint (e.g. "chrome", "firefox")
	ServerCertFingerprint  string // Expected server certificate SHA256 fingerprint (hex)
	IdleSessionCheckInterval time.Duration // Interval to check idle sessions
	IdleSessionTimeout       time.Duration // Timeout before closing idle sessions
	MinIdleSession           int           // Minimum number of idle sessions to maintain
}

type Flags uint64

const (
	Flags_VMess_UsePacketAddr = 1 << iota
)

const (
	Flags_Tuic_UdpRelayModeQuic = 1 << iota
)
