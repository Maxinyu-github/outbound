package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	utls "github.com/refraction-networking/utls"
)

var utlsClientHelloIDMap = map[string]*utls.ClientHelloID{
	"random":            &utls.HelloRandomized,
	"randomized":        &utls.HelloRandomized,
	"randomizedalpn":    &utls.HelloRandomizedALPN,
	"randomizednoalpn":  &utls.HelloRandomizedNoALPN,
	"firefox":           &utls.HelloFirefox_Auto,
	"firefox_auto":      &utls.HelloFirefox_Auto,
	"firefox_55":        &utls.HelloFirefox_55,
	"firefox_56":        &utls.HelloFirefox_56,
	"firefox_63":        &utls.HelloFirefox_63,
	"firefox_65":        &utls.HelloFirefox_65,
	"firefox_99":        &utls.HelloFirefox_99,
	"firefox_102":       &utls.HelloFirefox_102,
	"firefox_105":       &utls.HelloFirefox_105,
	"chrome":            &utls.HelloChrome_Auto,
	"chrome_auto":       &utls.HelloChrome_Auto,
	"chrome_58":         &utls.HelloChrome_58,
	"chrome_62":         &utls.HelloChrome_62,
	"chrome_70":         &utls.HelloChrome_70,
	"chrome_72":         &utls.HelloChrome_72,
	"chrome_83":         &utls.HelloChrome_83,
	"chrome_87":         &utls.HelloChrome_87,
	"chrome_96":         &utls.HelloChrome_96,
	"chrome_100":        &utls.HelloChrome_100,
	"chrome_102":        &utls.HelloChrome_102,
	"ios":               &utls.HelloIOS_Auto,
	"ios_auto":          &utls.HelloIOS_Auto,
	"ios_11_1":          &utls.HelloIOS_11_1,
	"ios_12_1":          &utls.HelloIOS_12_1,
	"ios_13":            &utls.HelloIOS_13,
	"ios_14":            &utls.HelloIOS_14,
	"android_11_okhttp": &utls.HelloAndroid_11_OkHttp,
	"edge":              &utls.HelloEdge_Auto,
	"edge_auto":         &utls.HelloEdge_Auto,
	"edge_85":           &utls.HelloEdge_85,
	"edge_106":          &utls.HelloEdge_106,
	"safari":            &utls.HelloSafari_Auto,
	"safari_auto":       &utls.HelloSafari_Auto,
	"safari_16_0":       &utls.HelloSafari_16_0,
	"360":               &utls.Hello360_Auto,
	"360_auto":          &utls.Hello360_Auto,
	"360_7_5":           &utls.Hello360_7_5,
	"360_11_0":          &utls.Hello360_11_0,
	"qq":                &utls.HelloQQ_Auto,
	"qq_auto":           &utls.HelloQQ_Auto,
	"qq_11_1":           &utls.HelloQQ_11_1,
}

func nameToUtlsClientHelloID(name string) (*utls.ClientHelloID, error) {
	clientHelloID, ok := utlsClientHelloIDMap[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown uTLS Client Hello ID: %s", name)
	}
	return clientHelloID, nil
}

func init() {
	protocol.Register("anytls", NewDialer)
}

type Dialer struct {
	proxyAddress          string
	nextDialer            netproxy.Dialer
	metadata              protocol.Metadata
	key                   []byte
	tlsConfig             *tls.Config
	utlsImitate           string
	serverCertFingerprint string
	idleCheckInterval     time.Duration
	idleTimeout           time.Duration
	minIdleSession        int

	sessionCounter atomic.Uint64

	idleSessionLock sync.Mutex
	idleSessions    map[uint64]*idleSessionEntry

	closed chan struct{}
}

type idleSessionEntry struct {
	session  *session
	idleSince time.Time
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	sum := sha256.Sum256([]byte(header.Password))

	idleCheckInterval := header.IdleSessionCheckInterval
	if idleCheckInterval <= 0 {
		idleCheckInterval = 30 * time.Second
	}
	idleTimeout := header.IdleSessionTimeout
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}

	d := &Dialer{
		proxyAddress:          header.ProxyAddress,
		nextDialer:            nextDialer,
		metadata:              metadata,
		key:                   sum[:],
		tlsConfig:             header.TlsConfig,
		utlsImitate:           header.UtlsImitate,
		serverCertFingerprint: strings.ToLower(strings.ReplaceAll(header.ServerCertFingerprint, ":", "")),
		idleCheckInterval:     idleCheckInterval,
		idleTimeout:           idleTimeout,
		minIdleSession:        header.MinIdleSession,
		idleSessions:          make(map[uint64]*idleSessionEntry),
		closed:                make(chan struct{}),
	}

	go d.idleSessionManager()

	return d, nil
}

func (d *Dialer) DialTcp(ctx context.Context, addr string) (c netproxy.Conn, err error) {
	return d.DialContext(ctx, "tcp", addr)
}

func (d *Dialer) DialUdp(ctx context.Context, addr string) (c netproxy.PacketConn, err error) {
	pktConn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	return pktConn.(netproxy.PacketConn), nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = d.metadata.IsClient
		if magicNetwork.Network == "udp" {
			mdata.Hostname = "sp.v2.udp-over-tcp.arpa"
		}
		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
			Mptcp:   magicNetwork.Mptcp,
		}.Encode()

		s, err := d.getSession(ctx, tcpNetwork)
		if err != nil {
			return nil, err
		}
		if magicNetwork.Network == "udp" {
			streamAddr := net.JoinHostPort(mdata.Hostname, strconv.Itoa(int(mdata.Port)))
			return s.newPacketStream(streamAddr, addr)
		}
		return s.newStream(addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}

func (d *Dialer) getSession(ctx context.Context, tcpNetwork string) (*session, error) {
	d.idleSessionLock.Lock()
	for seq := range d.idleSessions {
		entry := d.idleSessions[seq]
		delete(d.idleSessions, seq)
		if entry.session.closed.Load() {
			continue
		}
		d.idleSessionLock.Unlock()
		return entry.session, nil
	}
	d.idleSessionLock.Unlock()

	return d.createSession(ctx, tcpNetwork)
}

func (d *Dialer) createSession(ctx context.Context, tcpNetwork string) (*session, error) {
	rawConn, err := d.nextDialer.DialContext(ctx, tcpNetwork, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	conn := rawConn.(net.Conn)

	var tlsConn net.Conn
	if d.utlsImitate != "" {
		clientHelloID, err := nameToUtlsClientHelloID(d.utlsImitate)
		if err != nil {
			conn.Close()
			return nil, err
		}
		uConfig := &utls.Config{
			ServerName:         d.tlsConfig.ServerName,
			InsecureSkipVerify: d.tlsConfig.InsecureSkipVerify,
			NextProtos:         d.tlsConfig.NextProtos,
		}
		uConn := utls.UClient(conn, uConfig, *clientHelloID)
		if err := uConn.Handshake(); err != nil {
			uConn.Close()
			return nil, err
		}
		// Verify server certificate fingerprint for uTLS connections
		if d.serverCertFingerprint != "" {
			if err := d.verifyServerCertFingerprint(uConn.ConnectionState().PeerCertificates); err != nil {
				uConn.Close()
				return nil, err
			}
		}
		tlsConn = uConn
	} else {
		stdConn := tls.Client(conn, d.tlsConfig)
		if err := stdConn.Handshake(); err != nil {
			stdConn.Close()
			return nil, err
		}
		// Verify server certificate fingerprint for standard TLS connections
		if d.serverCertFingerprint != "" {
			if err := d.verifyServerCertFingerprint(stdConn.ConnectionState().PeerCertificates); err != nil {
				stdConn.Close()
				return nil, err
			}
		}
		tlsConn = stdConn
	}

	buf := pool.Get(len(d.key) + 2)
	defer pool.Put(buf)
	copy(buf, d.key)
	binary.BigEndian.PutUint16(buf[len(d.key):], uint16(0))
	if _, err := tlsConn.Write(buf); err != nil {
		tlsConn.Close()
		return nil, err
	}

	seq := d.sessionCounter.Add(1)
	s := newSession(tlsConn, seq)
	go func(s *session) {
		for range s.closeStreamChan {
			if s.closed.Load() {
				return
			}
			d.idleSessionLock.Lock()
			if _, ok := d.idleSessions[seq]; !ok {
				d.idleSessions[seq] = &idleSessionEntry{
					session:   s,
					idleSince: time.Now(),
				}
			}
			d.idleSessionLock.Unlock()
		}
	}(s)

	go s.run()

	return s, nil
}

func (d *Dialer) verifyServerCertFingerprint(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("anytls: server returned no certificates")
	}
	certHash := sha256.Sum256(certs[0].Raw)
	actualFingerprint := hex.EncodeToString(certHash[:])
	if actualFingerprint != d.serverCertFingerprint {
		return fmt.Errorf("anytls: server certificate fingerprint mismatch: expected %s, got %s",
			d.serverCertFingerprint, actualFingerprint)
	}
	return nil
}

func (d *Dialer) idleSessionManager() {
	ticker := time.NewTicker(d.idleCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.closed:
			return
		case <-ticker.C:
			d.cleanupIdleSessions()
		}
	}
}

func (d *Dialer) cleanupIdleSessions() {
	now := time.Now()
	d.idleSessionLock.Lock()
	defer d.idleSessionLock.Unlock()

	// Count alive idle sessions
	alive := 0
	for _, entry := range d.idleSessions {
		if !entry.session.closed.Load() {
			alive++
		}
	}

	// Close sessions that have been idle too long, but keep at least minIdleSession
	for seq, entry := range d.idleSessions {
		if entry.session.closed.Load() {
			delete(d.idleSessions, seq)
			continue
		}
		if now.Sub(entry.idleSince) > d.idleTimeout && alive > d.minIdleSession {
			slog.Debug("[anytls] closing idle session", slog.Uint64("seq", entry.session.seq))
			entry.session.Close()
			delete(d.idleSessions, seq)
			alive--
		}
	}
}
