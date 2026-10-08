package jls_test

// End-to-end coverage for protocols carried over JLS: share links go through
// the same link parser dae uses, and the jls-tls test server hands the
// authenticated stream to an in-test protocol server that echoes the payload.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/dialer"
	_ "github.com/daeuniverse/outbound/dialer/trojan"
	_ "github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/trojanc"
	_ "github.com/daeuniverse/outbound/protocol/vless"
	"github.com/daeuniverse/outbound/transport/jls"
)

const (
	e2eTarget    = "1.2.3.4:80"
	e2ePassword  = "trojan-password"
	e2eVlessUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
)

type tcpDialer struct{}

func (tcpDialer) DialContext(ctx context.Context, _, addr string) (netproxy.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// readAddress reads an address of the given type; the port precedes the
// address in VLESS and follows it in trojan.
func readAddress(r io.Reader, atyp byte, ipv4, domain, ipv6 byte, portFirst bool) (string, error) {
	var port [2]byte
	if portFirst {
		if _, err := io.ReadFull(r, port[:]); err != nil {
			return "", err
		}
	}
	var host string
	switch atyp {
	case ipv4, ipv6:
		ip := make(net.IP, 4)
		if atyp == ipv6 {
			ip = make(net.IP, 16)
		}
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		host = ip.String()
	case domain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", errors.New("unknown address type")
	}
	if !portFirst {
		if _, err := io.ReadFull(r, port[:]); err != nil {
			return "", err
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func serveTrojan(targets chan<- string) func(net.Conn) {
	return func(conn net.Conn) {
		// hex(SHA-224(password)) CRLF, command, address, CRLF, then payload.
		header := make([]byte, 56+2+1+1)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		hash := sha256.Sum224([]byte(e2ePassword))
		if string(header[:56]) != hex.EncodeToString(hash[:]) || header[58] != 1 {
			return
		}
		target, err := readAddress(conn, header[59], 1, 3, 4, false)
		if err != nil {
			return
		}
		if _, err := io.ReadFull(conn, header[:2]); err != nil {
			return
		}
		targets <- target
		_, _ = io.Copy(conn, conn)
	}
}

func serveVless(targets chan<- string) func(net.Conn) {
	return func(conn net.Conn) {
		// version, UUID, addons, command, port, address; the response is the
		// version and an empty addons length.
		header := make([]byte, 1+16+1)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		if header[0] != 0 || hex.EncodeToString(header[1:17]) != "b831381d63244d53ad4f8cda48b30811" {
			return
		}
		if _, err := io.CopyN(io.Discard, conn, int64(header[17])); err != nil {
			return
		}
		command := make([]byte, 1)
		if _, err := io.ReadFull(conn, command); err != nil || command[0] != 1 {
			return
		}
		var portAndType [3]byte
		if _, err := io.ReadFull(conn, portAndType[:]); err != nil {
			return
		}
		target, err := readAddress(io.MultiReader(bytes.NewReader(portAndType[:2]), conn), portAndType[2], 1, 2, 3, true)
		if err != nil {
			return
		}
		if _, err := conn.Write([]byte{0, 0}); err != nil {
			return
		}
		targets <- target
		_, _ = io.Copy(conn, conn)
	}
}

func TestE2EProtocolsOverJLS(t *testing.T) {
	jlsQuery := url.Values{
		"security":     {"jls"},
		"sni":          {jls.TestServerName},
		"jls-username": {jls.TestUsername},
		"jls-password": {jls.TestPassword},
	}
	for _, tc := range []struct {
		name  string
		serve func(chan<- string) func(net.Conn)
		link  func(addr string) string
	}{
		{
			name:  "trojan",
			serve: serveTrojan,
			link: func(addr string) string {
				u := url.URL{Scheme: "trojan", User: url.User(e2ePassword), Host: addr, RawQuery: jlsQuery.Encode()}
				return u.String()
			},
		},
		{
			name:  "vless-chrome",
			serve: serveVless,
			link: func(addr string) string {
				query := url.Values{"type": {"tcp"}, "fp": {"chrome"}}
				for key, values := range jlsQuery {
					query[key] = values
				}
				u := url.URL{Scheme: "vless", User: url.User(e2eVlessUUID), Host: addr, RawQuery: query.Encode()}
				return u.String()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets := make(chan string, 1)
			addr, results := jls.StartJLSServer(t, "", tc.serve(targets))
			d, _, err := dialer.NewNetproxyDialerFromLink(tcpDialer{}, &dialer.ExtraOption{}, tc.link(addr))
			if err != nil {
				t.Fatalf("NewNetproxyDialerFromLink: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := d.DialContext(ctx, "tcp", e2eTarget)
			if err != nil {
				t.Fatalf("DialContext: %v", err)
			}
			defer conn.Close()

			payload := []byte("hello over " + tc.name + " and jls")
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("echo = %q, want %q", got, payload)
			}
			if result := <-results; result.Err() != nil {
				t.Fatalf("server handshake: %v", result.Err())
			}
			if target := <-targets; target != e2eTarget {
				t.Fatalf("server target = %q, want %q", target, e2eTarget)
			}
		})
	}
}
