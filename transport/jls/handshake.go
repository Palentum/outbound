package jls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	gotls "crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/daeuniverse/outbound/pkg/coalesce"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	typeClientHello = 1
	typeServerHello = 2
	// A handshake message starts with its type and uint24 length, then the
	// legacy version and the 32-byte random.
	randomOffset  = 4 + 2
	randomLen     = 32
	randomSeedLen = randomLen / 2

	downgradeCanaryTLS12          = "DOWNGRD\x01"
	downgradeCanaryTLS11          = "DOWNGRD\x00"
	helloRetryRequestRandomSuffix = "\x07\x9e\x09\xe2\xc8\xa8\x33\x9c"

	// clientHelloAttempts bounds the rebuilds for fingerprints that only
	// sometimes offer a usable TLS 1.3 key share. JLS forbids
	// HelloRetryRequest, so a hello that invites one cannot authenticate.
	// uTLS's randomized fingerprint yields a usable hello 26% of the time
	// (5000 builds), so 64 attempts fail with probability 0.74^64 = 4e-9.
	clientHelloAttempts = 64
)

func (j *JLS) handshake(ctx context.Context, co *coalesce.Conn) (*utls.UConn, error) {
	uConn, v, err := j.newClient(co)
	if err != nil {
		return nil, err
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !v.authenticated {
		// The server proved a valid certificate for the website behind the
		// SNI, so finish like a browser before reporting the failure.
		j.fallbackRequest(ctx, &flushConn{UConn: uConn, co: co})
		return nil, ErrAuthFailed
	}
	if uConn.ConnectionState().Version != utls.VersionTLS13 {
		return nil, ErrAuthFailed
	}
	return uConn, nil
}

// newClient builds the fingerprint's ClientHello and replaces its random with
// the JLS proof. JLS authenticates the exact serialized hello with the random
// zeroed, so the hello must be final before the random is sealed.
func (j *JLS) newClient(conn net.Conn) (*utls.UConn, *verifier, error) {
	golang := j.clientHelloID.Client == utls.HelloGolang.Client
	alpn := j.alpn
	if alpn == nil {
		alpn = defaultALPN
	}
	for attempt := 1; ; attempt++ {
		v := &verifier{user: j.user, serverName: j.serverName, rootCAs: j.rootCAs}
		// Resumption would need the PSK binders recomputed after the random
		// changes, which uTLS has no hook for, so tickets stay disabled.
		uConn := utls.UClient(conn, &utls.Config{
			ServerName: j.serverName,
			NextProtos: slices.Clone(alpn),
			// The verifier authenticates the server through JLS, or falls
			// back to verifying the certificate itself.
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			VerifyConnection:       v.verifyConnection,
		}, j.clientHelloID)
		v.uConn = uConn
		if err := uConn.BuildHandshakeState(); err != nil {
			return nil, nil, err
		}
		// A parrot takes its ALPN from its extension list, not the config.
		if j.alpn != nil && !golang {
			overrideALPN(uConn, j.alpn)
			if err := uConn.ApplyConfig(); err != nil {
				return nil, nil, err
			}
			if err := uConn.MarshalClientHello(); err != nil {
				return nil, nil, err
			}
		}
		if !offersTLS13KeyShare(uConn.HandshakeState.Hello) {
			if attempt < clientHelloAttempts {
				continue
			}
			return nil, nil, fmt.Errorf("jls: fingerprint %s %s does not offer a TLS 1.3 key share", j.clientHelloID.Client, j.clientHelloID.Version)
		}

		raw, err := marshaledClientHello(uConn)
		if err != nil {
			return nil, nil, err
		}
		authData, err := helloAuthData(raw, typeClientHello)
		if err != nil {
			return nil, nil, err
		}
		hello := uConn.HandshakeState.Hello
		fakeRandom, err := buildFakeRandom(j.user, hello.Random[:randomSeedLen], authData, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		if err := uConn.SetClientRandom(fakeRandom); err != nil {
			return nil, nil, err
		}
		// The Go hello is marshaled from its fields when it is sent; a parrot
		// sends the bytes marshaled here.
		if !golang {
			if err := uConn.MarshalClientHello(); err != nil {
				return nil, nil, err
			}
		}
		if v.clientHello, err = marshaledClientHello(uConn); err != nil {
			return nil, nil, err
		}
		return uConn, v, nil
	}
}

func marshaledClientHello(uConn *utls.UConn) ([]byte, error) {
	hello := uConn.HandshakeState.Hello
	if len(hello.Raw) > 0 {
		return slices.Clone(hello.Raw), nil
	}
	return hello.Marshal()
}

func offersTLS13KeyShare(hello *utls.PubClientHelloMsg) bool {
	if !slices.Contains(hello.SupportedVersions, utls.VersionTLS13) {
		return false
	}
	hasKeyShare := func(group utls.CurveID) bool {
		return slices.ContainsFunc(hello.KeyShares, func(keyShare utls.KeyShare) bool {
			return keyShare.Group == group
		})
	}
	// Servers that prefer post-quantum groups (Go 1.24+) answer an advertised
	// hybrid group without a key share with a HelloRetryRequest.
	if slices.Contains(hello.SupportedCurves, utls.X25519MLKEM768) && !hasKeyShare(utls.X25519MLKEM768) {
		return false
	}
	return slices.ContainsFunc(hello.KeyShares, func(keyShare utls.KeyShare) bool {
		return !isGREASE(uint16(keyShare.Group))
	})
}

func isGREASE(v uint16) bool {
	return v>>8 == v&0xff && v&0xf == 0xa
}

// overrideALPN replaces the parrot's ALPN and keeps ALPS only while h2 stays
// advertised.
func overrideALPN(uConn *utls.UConn, protocols []string) {
	hasH2 := slices.Contains(protocols, "h2")
	hasALPN := false
	extensions := uConn.Extensions[:0]
	for _, extension := range uConn.Extensions {
		switch extension := extension.(type) {
		case *utls.ALPNExtension:
			extension.AlpnProtocols = slices.Clone(protocols)
			hasALPN = true
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			if !hasH2 {
				continue
			}
		}
		extensions = append(extensions, extension)
	}
	if !hasALPN {
		extensions = append(extensions, &utls.ALPNExtension{AlpnProtocols: slices.Clone(protocols)})
	}
	uConn.Extensions = extensions
}

type verifier struct {
	uConn         *utls.UConn
	user          user
	serverName    string
	rootCAs       *x509.CertPool
	clientHello   []byte
	authenticated bool
}

func (v *verifier) verifyConnection(state utls.ConnectionState) error {
	// JLS forbids HelloRetryRequest; uTLS replaces the hello when it sends a
	// second one.
	if hello, err := marshaledClientHello(v.uConn); err != nil || !bytes.Equal(v.clientHello, hello) {
		return v.verifyCertificate(state)
	}
	serverHello := v.uConn.HandshakeState.ServerHello
	if serverHello == nil {
		return errors.New("jls: server hello is unavailable")
	}
	authData, err := helloAuthData(serverHello.Raw, typeServerHello)
	if err != nil {
		return err
	}
	if !checkFakeRandom(v.user, serverHello.Random, authData) {
		return v.verifyCertificate(state)
	}
	v.authenticated = true
	return nil
}

func (v *verifier) verifyCertificate(state utls.ConnectionState) error {
	certificates := state.PeerCertificates
	if len(certificates) == 0 {
		return errors.New("jls: unauthenticated server sent no certificate")
	}
	opts := x509.VerifyOptions{
		Roots:         v.rootCAs,
		DNSName:       v.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, certificate := range certificates[1:] {
		opts.Intermediates.AddCert(certificate)
	}
	if _, err := certificates[0].Verify(opts); err != nil {
		return fmt.Errorf("jls: unauthenticated server: %w", err)
	}
	return nil
}

// flushConn flushes the coalescer after every write. The HTTP clients read
// and write from separate goroutines, so a read already blocked on the socket
// would never flush a later request.
type flushConn struct {
	*utls.UConn
	co *coalesce.Conn
}

func (c *flushConn) Write(b []byte) (int, error) {
	n, err := c.UConn.Write(b)
	if ferr := c.co.Flush(); err == nil {
		err = ferr
	}
	return n, err
}

// fallbackRequest sends one plausible request over the established
// connection, then closes it.
func (j *JLS) fallbackRequest(ctx context.Context, conn *flushConn) {
	defer conn.Close()
	var transport http.RoundTripper
	if conn.ConnectionState().NegotiatedProtocol == "h2" {
		transport = &http2.Transport{
			DialTLSContext: func(context.Context, string, string, *gotls.Config) (net.Conn, error) {
				return conn, nil
			},
		}
	} else {
		transport = &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				return conn, nil
			},
		}
	}
	client := &http.Client{Transport: transport}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+j.serverName, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", j.clientHelloID.Client)
	req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", 30+mrand.IntN(32))})
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// helloAuthData returns a copy of the handshake message with its random
// zeroed, the associated data of the JLS proof.
func helloAuthData(raw []byte, messageType byte) ([]byte, error) {
	if len(raw) < randomOffset+randomLen ||
		raw[0] != messageType ||
		int(raw[1])<<16|int(raw[2])<<8|int(raw[3]) != len(raw)-4 {
		return nil, errors.New("jls: invalid hello message")
	}
	authData := slices.Clone(raw)
	clear(authData[randomOffset : randomOffset+randomLen])
	return authData, nil
}

// buildFakeRandom seals the 16-byte seed into the 32-byte hello random.
func buildFakeRandom(u user, seed, authData []byte, random io.Reader) ([]byte, error) {
	if len(seed) != randomSeedLen {
		return nil, errors.New("jls: random seed must be 16 bytes")
	}
	aead, nonce, err := newAEAD(u, authData)
	if err != nil {
		return nil, err
	}
	seed = slices.Clone(seed)
	// JLS reserves the TLS downgrade canaries and the HelloRetryRequest random
	// suffix; draw a new seed instead of sending one of them.
	for {
		fakeRandom := aead.Seal(nil, nonce[:], seed, nil)
		if !hasForbiddenRandomSuffix(fakeRandom) {
			return fakeRandom, nil
		}
		if _, err := io.ReadFull(random, seed); err != nil {
			return nil, err
		}
	}
}

func hasForbiddenRandomSuffix(random []byte) bool {
	suffix := string(random[len(random)-len(downgradeCanaryTLS12):])
	return suffix == downgradeCanaryTLS12 ||
		suffix == downgradeCanaryTLS11 ||
		suffix == helloRetryRequestRandomSuffix
}

func checkFakeRandom(u user, fakeRandom, authData []byte) bool {
	if len(fakeRandom) != randomLen {
		return false
	}
	aead, nonce, err := newAEAD(u, authData)
	if err != nil {
		return false
	}
	seed, err := aead.Open(nil, nonce[:], fakeRandom, nil)
	return err == nil && len(seed) == randomSeedLen
}

// newAEAD derives AES-256-GCM with a 32-byte nonce from the credentials and
// the hello: key = SHA-256(password || authData), nonce = SHA-256(username ||
// authData).
func newAEAD(u user, authData []byte) (cipher.AEAD, [sha256.Size]byte, error) {
	nonce := sha256.Sum256(append([]byte(u.username), authData...))
	key := sha256.Sum256(append([]byte(u.password), authData...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nonce, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	return aead, nonce, err
}
