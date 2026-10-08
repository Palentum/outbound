package anytls_test

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	anytlsprotocol "github.com/daeuniverse/outbound/protocol/anytls"
)

// writeRecorder is a plain TCP next dialer that records the size of every
// Write on its conns. It stands in for a security layer such as JLS, which
// turns each write into its own TLS record.
type writeRecorder struct {
	mu     sync.Mutex
	writes []int
}

func (r *writeRecorder) DialContext(ctx context.Context, _, addr string) (netproxy.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &recordingConn{Conn: c, r: r}, nil
}

func (r *writeRecorder) sizes() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.writes...)
}

type recordingConn struct {
	net.Conn
	r *writeRecorder
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.r.mu.Lock()
	c.r.writes = append(c.r.writes, len(b))
	c.r.mu.Unlock()
	return c.Conn.Write(b)
}

// startPlainAnytlsServer runs the in-test server over plain TCP, so the
// session starts directly with the authentication packet.
func startPlainAnytlsServer(t *testing.T, password string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("anytls listen: %v", err)
	}
	s := &e2eAnytlsServer{t: t, password: password, ln: ln}
	s.live.Store(true)
	t.Cleanup(func() {
		s.live.Store(false)
		_ = ln.Close()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			ss := &e2eSession{
				srv:     s,
				conn:    c,
				streams: map[uint32]*e2eStream{},
				wantKey: sha256.Sum256([]byte(password)),
			}
			go func() {
				if err := ss.serve(); err != nil && s.inTest() {
					s.t.Logf("anytls plain session ended: %v", err)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// TestE2EAnytlsNilTLSConfigUsesNextDialerAsSecurityLayer relays through a
// session built with a nil TlsConfig, the form dialer/anytls uses when JLS
// secures the connection.
func TestE2EAnytlsNilTLSConfigUsesNextDialerAsSecurityLayer(t *testing.T) {
	echoAddr := loopbackEchoTarget(t)
	proxyAddr := startPlainAnytlsServer(t, "anytls-plain-password")
	next := &writeRecorder{}
	d, err := anytlsprotocol.NewDialer(next, protocol.Header{
		ProxyAddress: proxyAddr,
		Password:     "anytls-plain-password",
		IsClient:     true,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	defer d.(io.Closer).Close()

	c, err := d.DialContext(deadlineCtx(t), "tcp", echoAddr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	verifyRelayRoundTrip(t, c, 1<<20, 21)

	// Each padded write must reach the security layer on its own, or its
	// record sizes no longer follow the padding scheme. Under the default
	// scheme packet 0 is the 64-byte authentication packet (32-byte key,
	// 2-byte length, 30 bytes of padding) and packet 1 one 100-400 byte write.
	writes := next.sizes()
	if len(writes) < 2 || writes[0] != 64 || writes[1] < 100 || writes[1] > 400 {
		t.Fatalf("first writes = %v, want [64 100..400 ...]", writes[:min(len(writes), 4)])
	}
}
