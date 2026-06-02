package anytls

import (
	"crypto/tls"
	"net/url"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	dialer.FromLinkRegister("anytls", NewAnytls)
}

type Anytls struct {
	link              string
	Name              string
	Auth              string
	Host              string
	Sni               string
	Insecure          bool
	ClientFingerprint string   // uTLS client hello fingerprint (e.g. "chrome")
	Alpn              []string // ALPN protocols (e.g. ["h2"])
}

func NewAnytls(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	switch {
	case strings.HasPrefix(link, "anytls://"):
		s, err := parseAnytlsURL(link)
		if err != nil {
			return nil, nil, err
		}
		// Apply global options if not set per-node
		if s.ClientFingerprint == "" && option.UtlsImitate != "" {
			s.ClientFingerprint = option.UtlsImitate
		}
		return s.Dialer(option, nextDialer)
	default:
		return nil, nil, dialer.InvalidParameterErr
	}
}

func parseAnytlsURL(link string) (*Anytls, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	sni := u.Query().Get("peer")
	if sni == "" {
		sni = u.Query().Get("sni")
	}
	if sni == "" {
		sni = u.Hostname()
	}

	clientFingerprint := u.Query().Get("client-fingerprint")
	if clientFingerprint == "" {
		clientFingerprint = u.Query().Get("clientFingerprint")
	}

	var alpn []string
	if alpnStr := u.Query().Get("alpn"); alpnStr != "" {
		alpn = strings.Split(alpnStr, ",")
	}

	antls := &Anytls{
		link:              link,
		Name:              u.Fragment,
		Auth:              u.User.Username(),
		Host:              u.Host,
		Sni:               sni,
		Insecure:          u.Query().Get("insecure") == "1",
		ClientFingerprint: clientFingerprint,
		Alpn:              alpn,
	}

	return antls, nil
}

func (s *Anytls) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, *dialer.Property, error) {
	tlsConfig := &tls.Config{
		ServerName:         s.Sni,
		InsecureSkipVerify: s.Insecure || option.AllowInsecure,
	}
	if tlsConfig.ServerName == "" {
		// disable the SNI
		tlsConfig.ServerName = "127.0.0.1"
	}
	if len(s.Alpn) > 0 {
		tlsConfig.NextProtos = s.Alpn
	}
	d, err := protocol.NewDialer("anytls", nextDialer, protocol.Header{
		ProxyAddress: s.Host,
		Password:     s.Auth,
		IsClient:     true,
		TlsConfig:    tlsConfig,
		UtlsImitate:  s.ClientFingerprint,
	})
	if err != nil {
		return nil, nil, err
	}
	return d, &dialer.Property{
		Name:     s.Name,
		Protocol: "anytls",
		Address:  s.Host,
		Link:     s.link,
	}, nil
}
