package protocol

import "crypto/tls"

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
	UtlsImitate  string // uTLS client hello fingerprint (e.g. "chrome", "firefox")
}

type Flags uint64

const (
	Flags_VMess_UsePacketAddr = 1 << iota
)

const (
	Flags_Tuic_UdpRelayModeQuic = 1 << iota
)
