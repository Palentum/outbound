// Package jls implements the client side of JLS
// (https://github.com/JimmyHuang454/JLS): a TLS 1.3 handshake whose client and
// server randoms carry an AEAD proof of a pre-shared username and password, so
// the server authenticates without a certificate of its own and passes for the
// website named in the SNI. The handshake follows the uTLS client in
// MetaCubeX/mihomo (transport/jls), which interoperates with rustls-jls and
// jls-tls servers.
package jls

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/coalesce"
	outboundtls "github.com/daeuniverse/outbound/transport/tls"
	utls "github.com/refraction-networking/utls"
)

func init() {
	dialer.FromLinkRegister("jls", NewJLS)
}

// ErrAuthFailed reports a server that completed the TLS handshake without
// proving the JLS credentials, i.e. the real website behind the SNI.
var ErrAuthFailed = errors.New("jls: authentication failed")

// defaultALPN is offered when neither the link nor the fingerprint sets one.
var defaultALPN = []string{"h2", "http/1.1"}

type user struct {
	username string
	password string
}

type JLS struct {
	nextDialer    netproxy.Dialer
	addr          string
	serverName    string
	user          user
	alpn          []string
	clientHelloID utls.ClientHelloID
	// rootCAs verifies the certificate of a server that fails JLS
	// authentication; nil uses the system roots.
	rootCAs *x509.CertPool
}

func (j *JLS) UnwrapDialer() netproxy.Dialer {
	return j.nextDialer
}

// NewJLS parses jls://host:port?username=&password=[&sni=][&alpn=][&fp=].
// sni defaults to the link host. fp selects a uTLS fingerprint; without it the
// global utls_imitate applies when tls_implementation is utls, and the Go
// crypto/tls ClientHello otherwise.
func NewJLS(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewJLS: %w", err)
	}
	if _, _, err = net.SplitHostPort(u.Host); err != nil {
		return nil, nil, fmt.Errorf("NewJLS: invalid server address %q: %w", u.Host, err)
	}
	query := u.Query()
	j := &JLS{
		nextDialer: nextDialer,
		addr:       u.Host,
		serverName: query.Get("sni"),
		user: user{
			username: query.Get("username"),
			password: query.Get("password"),
		},
		clientHelloID: utls.HelloGolang,
	}
	if j.user.username == "" {
		return nil, nil, fmt.Errorf("NewJLS: username is required")
	}
	if j.user.password == "" {
		return nil, nil, fmt.Errorf("NewJLS: password is required")
	}
	if j.serverName == "" {
		j.serverName = u.Hostname()
	}
	if alpn := query.Get("alpn"); alpn != "" {
		j.alpn = strings.Split(alpn, ",")
	}
	fingerprint := query.Get("fp")
	if fingerprint == "" && option != nil && option.TlsImplementation == "utls" {
		fingerprint = option.UtlsImitate
	}
	if fingerprint != "" {
		clientHelloID, err := outboundtls.NameToUTLSClientHelloID(fingerprint)
		if err != nil {
			return nil, nil, fmt.Errorf("NewJLS: %w", err)
		}
		j.clientHelloID = *clientHelloID
	}
	return j, &dialer.Property{
		Name:     u.Fragment,
		Address:  j.addr,
		Protocol: "jls",
		Link:     link,
	}, nil
}

func (j *JLS) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if magicNetwork.Network != "tcp" {
		return nil, fmt.Errorf("%w: jls+%v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
	rc, err := j.nextDialer.DialContext(ctx, network, j.addr)
	if err != nil {
		return nil, fmt.Errorf("[JLS]: dial to %s: %w", j.addr, err)
	}
	// Coalesce the TLS records of one write burst into one socket write, as
	// transport/tls does.
	co := coalesce.New(&netproxy.FakeNetConn{Conn: rc})
	uConn, err := j.handshake(ctx, co)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	if err := co.Flush(); err != nil {
		_ = uConn.Close()
		return nil, err
	}
	return coalesce.NewFlushConn(uConn, co), nil
}
