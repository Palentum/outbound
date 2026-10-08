package jls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	jlstls "github.com/metacubex/jls-tls"
)

const (
	testUsername   = "jls-user"
	testPassword   = "jls-password"
	testServerName = "example.com"
)

type tcpDialer struct{}

func (tcpDialer) DialContext(ctx context.Context, _, addr string) (netproxy.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func newTestJLS(t *testing.T, option *dialer.ExtraOption, addr string, query url.Values) *JLS {
	t.Helper()
	u := url.URL{Scheme: "jls", Host: addr, RawQuery: query.Encode()}
	d, _, err := NewJLS(option, tcpDialer{}, u.String())
	if err != nil {
		t.Fatalf("NewJLS: %v", err)
	}
	return d.(*JLS)
}

func credentials(username, password string) url.Values {
	return url.Values{
		"sni":      {testServerName},
		"username": {username},
		"password": {password},
	}
}

func selfSignedCertificate(t *testing.T) jlstls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jls"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return jlstls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type serverResult struct {
	state jlstls.ConnectionState
	err   error
}

// recordingConn keeps what the client sent during the server handshake so a
// rejected handshake can be replayed to the fallback website.
type recordingConn struct {
	net.Conn
	read bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Write(p[:n])
	return n, err
}

// startJLSServer runs a jls-tls server that echoes authenticated connections
// and, like a deployed JLS server, relays rejected ones to fallback.
func startJLSServer(t *testing.T, fallback string) (string, <-chan serverResult) {
	return startJLSServerWith(t, fallback, func(conn net.Conn) { _, _ = io.Copy(conn, conn) })
}

// startJLSServerWith hands authenticated connections to serve.
func startJLSServerWith(t *testing.T, fallback string, serve func(net.Conn)) (string, <-chan serverResult) {
	t.Helper()
	config := &jlstls.Config{
		Certificates: []jlstls.Certificate{selfSignedCertificate(t)},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   jlstls.VersionTLS13,
		JLSConfig: &jlstls.JLSConfig{
			Enable:     true,
			Users:      []jlstls.JLSUser{{Username: testUsername, Password: testPassword}},
			ServerName: testServerName,
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	results := make(chan serverResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		recorder := &recordingConn{Conn: conn}
		server := jlstls.Server(recorder, config)
		if err := server.Handshake(); err != nil {
			results <- serverResult{err: err}
			if fallback == "" {
				return
			}
			upstream, err := net.Dial("tcp", fallback)
			if err != nil {
				return
			}
			defer upstream.Close()
			if _, err := upstream.Write(recorder.read.Bytes()); err != nil {
				return
			}
			go func() { _, _ = io.Copy(upstream, conn) }()
			_, _ = io.Copy(conn, upstream)
			return
		}
		results <- serverResult{state: server.ConnectionState()}
		serve(server)
	}()
	return ln.Addr().String(), results
}

func echo(t *testing.T, conn netproxy.Conn) {
	t.Helper()
	payload := []byte("hello through jls")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}

func TestJLSInteropWithJLSTLSServer(t *testing.T) {
	for _, fp := range []string{"", "chrome", "firefox", "safari", "ios", "edge", "randomized"} {
		t.Run("fp="+fp, func(t *testing.T) {
			addr, results := startJLSServer(t, "")
			query := credentials(testUsername, testPassword)
			if fp != "" {
				query.Set("fp", fp)
			}
			conn, err := newTestJLS(t, nil, addr, query).DialContext(testContext(t), "tcp", "ignored:443")
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer conn.Close()
			result := <-results
			if result.err != nil {
				t.Fatalf("server handshake: %v", result.err)
			}
			if result.state.JLS.Status != jlstls.JLSAuthenticated || result.state.JLS.User != testUsername {
				t.Fatalf("server JLS state = %+v, want user %q authenticated", result.state.JLS, testUsername)
			}
			echo(t, conn)
		})
	}
}

func TestJLSALPNOverride(t *testing.T) {
	for _, fp := range []string{"", "chrome"} {
		t.Run("fp="+fp, func(t *testing.T) {
			addr, results := startJLSServer(t, "")
			query := credentials(testUsername, testPassword)
			query.Set("alpn", "http/1.1")
			if fp != "" {
				query.Set("fp", fp)
			}
			conn, err := newTestJLS(t, nil, addr, query).DialContext(testContext(t), "tcp", "ignored:443")
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer conn.Close()
			result := <-results
			if result.err != nil {
				t.Fatalf("server handshake: %v", result.err)
			}
			if got := result.state.NegotiatedProtocol; got != "http/1.1" {
				t.Fatalf("negotiated ALPN = %q, want http/1.1", got)
			}
		})
	}
}

// startFallbackWebsite serves the website a JLS server borrows the identity of.
func startFallbackWebsite(t *testing.T, enableHTTP2 bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	website := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("padding"); err == nil && strings.Trim(cookie.Value, "0") == "" {
			requests.Add(1)
		}
		_, _ = io.WriteString(w, "website")
	}))
	website.EnableHTTP2 = enableHTTP2
	website.StartTLS()
	t.Cleanup(website.Close)
	return website, &requests
}

func TestJLSWrongPasswordFallsBackToWebsite(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fp    string
		alpn  string
		http2 bool
	}{
		{name: "golang-h2", http2: true},
		{name: "chrome-h2", fp: "chrome", http2: true},
		{name: "chrome-http1", fp: "chrome", alpn: "http/1.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			website, requests := startFallbackWebsite(t, tc.http2)
			addr, results := startJLSServer(t, website.Listener.Addr().String())
			query := credentials(testUsername, "wrong-password")
			if tc.fp != "" {
				query.Set("fp", tc.fp)
			}
			if tc.alpn != "" {
				query.Set("alpn", tc.alpn)
			}
			j := newTestJLS(t, nil, addr, query)
			j.rootCAs = x509.NewCertPool()
			j.rootCAs.AddCert(website.Certificate())

			conn, err := j.DialContext(testContext(t), "tcp", "ignored:443")
			if !errors.Is(err, ErrAuthFailed) {
				if conn != nil {
					_ = conn.Close()
				}
				t.Fatalf("DialContext error = %v, want %v", err, ErrAuthFailed)
			}
			if result := <-results; result.err == nil {
				t.Fatal("server authenticated a wrong password")
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("fallback website got %d padded requests, want 1", got)
			}
		})
	}
}

func TestJLSRejectsUntrustedUnauthenticatedServer(t *testing.T) {
	website, requests := startFallbackWebsite(t, true)
	// The website's certificate is not in the system roots.
	j := newTestJLS(t, nil, website.Listener.Addr().String(), credentials(testUsername, testPassword))
	conn, err := j.DialContext(testContext(t), "tcp", "ignored:443")
	if err == nil {
		_ = conn.Close()
		t.Fatal("DialContext succeeded against an unauthenticated server")
	}
	if errors.Is(err, ErrAuthFailed) || !strings.Contains(err.Error(), "jls: unauthenticated server") {
		t.Fatalf("DialContext error = %v, want a certificate error", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("website got %d requests over an unverified connection", got)
	}
}

func TestNewJLS(t *testing.T) {
	utlsOption := &dialer.ExtraOption{TlsImplementation: "utls", UtlsImitate: "firefox"}
	for _, tc := range []struct {
		name       string
		option     *dialer.ExtraOption
		link       string
		wantErr    string
		wantSNI    string
		wantClient string
	}{
		{name: "defaults", link: "jls://1.2.3.4:443?username=u&password=p", wantSNI: "1.2.3.4", wantClient: "Golang"},
		{name: "global utls", option: utlsOption, link: "jls://h:443?username=u&password=p&sni=s", wantSNI: "s", wantClient: "Firefox"},
		{name: "link fp wins", option: utlsOption, link: "jls://h:443?username=u&password=p&fp=chrome", wantSNI: "h", wantClient: "Chrome"},
		{name: "global tls ignores utls_imitate", option: &dialer.ExtraOption{TlsImplementation: "tls", UtlsImitate: "firefox"}, link: "jls://h:443?username=u&password=p", wantSNI: "h", wantClient: "Golang"},
		{name: "missing username", link: "jls://h:443?password=p", wantErr: "username is required"},
		{name: "missing password", link: "jls://h:443?username=u", wantErr: "password is required"},
		{name: "unknown fp", link: "jls://h:443?username=u&password=p&fp=nope", wantErr: "unknown uTLS Client Hello ID"},
		{name: "missing port", link: "jls://h?username=u&password=p", wantErr: "invalid server address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _, err := NewJLS(tc.option, tcpDialer{}, tc.link)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("NewJLS error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewJLS: %v", err)
			}
			j := d.(*JLS)
			if j.serverName != tc.wantSNI || j.clientHelloID.Client != tc.wantClient {
				t.Fatalf("sni=%q client=%q, want sni=%q client=%q", j.serverName, j.clientHelloID.Client, tc.wantSNI, tc.wantClient)
			}
		})
	}
}
