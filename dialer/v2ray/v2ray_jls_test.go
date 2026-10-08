package v2ray_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/dialer/v2ray"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/vless"
	_ "github.com/daeuniverse/outbound/protocol/vmess"
	"github.com/daeuniverse/outbound/transport/jls"
	"github.com/daeuniverse/outbound/transport/ws"
)

const jlsTestUUID = "00000000-0000-0000-0000-000000000001"

type jlsNoopDialer struct{}

func (jlsNoopDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errors.New("noop dialer")
}

// findLayer returns the first dialer of type T found by unwrapping d.
func findLayer[T netproxy.Dialer](t *testing.T, d netproxy.Dialer) T {
	t.Helper()
	for d != nil {
		if layer, ok := d.(T); ok {
			return layer
		}
		u, ok := d.(interface{ UnwrapDialer() netproxy.Dialer })
		if !ok {
			break
		}
		d = u.UnwrapDialer()
	}
	var zero T
	t.Fatalf("no %T layer in the dialer chain", zero)
	return zero
}

func jlsALPN(j reflect.Value) []string {
	alpn := j.FieldByName("alpn")
	out := make([]string, alpn.Len())
	for i := range out {
		out[i] = alpn.Index(i).String()
	}
	return out
}

func TestParseVlessURLJLS(t *testing.T) {
	link := "vless://" + jlsTestUUID + "@127.0.0.1:443?type=tcp&security=jls&jls-username=u&jls-password=p&sni=www.example.com&alpn=h2&fp=chrome#n"
	s, err := v2ray.ParseVlessURL(link)
	if err != nil {
		t.Fatalf("ParseVlessURL failed: %v", err)
	}
	if s.TLS != "jls" || s.JlsUsername != "u" || s.JlsPassword != "p" {
		t.Fatalf("parsed security = %q, jls user = %q, jls password = %q", s.TLS, s.JlsUsername, s.JlsPassword)
	}
	again, err := v2ray.ParseVlessURL(s.ExportToURL())
	if err != nil {
		t.Fatalf("ParseVlessURL(export) failed: %v", err)
	}
	if !reflect.DeepEqual(again, s) {
		t.Fatalf("export round trip = %+v, want %+v", again, s)
	}
}

func TestParseVmessURLJLS(t *testing.T) {
	raw, err := json.Marshal(map[string]string{
		"v": "2", "ps": "n", "add": "127.0.0.1", "port": "443", "id": jlsTestUUID, "aid": "0",
		"net": "ws", "host": "cdn.example.com", "path": "/ws", "tls": "jls", "sni": "www.example.com",
		"jls-username": "u", "jls-password": "p",
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := v2ray.ParseVmessURL("vmess://" + base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("ParseVmessURL failed: %v", err)
	}
	if s.TLS != "jls" || s.JlsUsername != "u" || s.JlsPassword != "p" {
		t.Fatalf("parsed tls = %q, jls user = %q, jls password = %q", s.TLS, s.JlsUsername, s.JlsPassword)
	}
	again, err := v2ray.ParseVmessURL(s.ExportToURL())
	if err != nil {
		t.Fatalf("ParseVmessURL(export) failed: %v", err)
	}
	if !reflect.DeepEqual(again, s) {
		t.Fatalf("export round trip = %+v, want %+v", again, s)
	}
}

func TestV2RayDialerJLS(t *testing.T) {
	tests := []struct {
		name           string
		s              v2ray.V2Ray
		wantServerName string
		wantALPN       []string
	}{
		{
			name:           "vless tcp",
			s:              v2ray.V2Ray{Protocol: "vless", Net: "tcp", SNI: "www.example.com", Alpn: "h2", Fingerprint: "chrome"},
			wantServerName: "www.example.com",
			wantALPN:       []string{"h2"},
		},
		{
			name:           "vmess tcp host as sni",
			s:              v2ray.V2Ray{Protocol: "vmess", Net: "tcp", Host: "cdn.example.com"},
			wantServerName: "cdn.example.com",
			wantALPN:       []string{},
		},
		{
			name:           "vmess tcp server as sni",
			s:              v2ray.V2Ray{Protocol: "vmess", Net: "tcp"},
			wantServerName: "127.0.0.1",
			wantALPN:       []string{},
		},
		{
			name:           "vless ws",
			s:              v2ray.V2Ray{Protocol: "vless", Net: "ws", SNI: "www.example.com", Host: "cdn.example.com", Path: "/ws"},
			wantServerName: "www.example.com",
			wantALPN:       []string{"http/1.1"},
		},
		{
			name:           "vmess httpupgrade",
			s:              v2ray.V2Ray{Protocol: "vmess", Net: "httpupgrade", SNI: "www.example.com", Path: "/up"},
			wantServerName: "www.example.com",
			wantALPN:       []string{"http/1.1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.s
			s.Add, s.Port, s.ID, s.TLS, s.JlsUsername, s.JlsPassword = "127.0.0.1", "443", jlsTestUUID, "jls", "u", "p"
			d, property, err := s.Dialer(&dialer.ExtraOption{}, jlsNoopDialer{})
			if err != nil {
				t.Fatalf("Dialer() error = %v", err)
			}
			if s.Protocol == "vless" && !strings.Contains(property.Link, "jls-username=u") {
				t.Fatalf("exported link lost the jls credentials: %q", property.Link)
			}
			j := reflect.ValueOf(findLayer[*jls.JLS](t, d)).Elem()
			if got := j.FieldByName("serverName").String(); got != tt.wantServerName {
				t.Fatalf("server name = %q, want %q", got, tt.wantServerName)
			}
			if got := jlsALPN(j); !slices.Equal(got, tt.wantALPN) {
				t.Fatalf("alpn = %q, want %q", got, tt.wantALPN)
			}
			if s.Net == "ws" {
				// JLS is the security layer, so the websocket itself is plain.
				w := reflect.ValueOf(findLayer[*ws.Ws](t, d)).Elem()
				if addr := w.FieldByName("wsAddr").String(); !strings.HasPrefix(addr, "ws://") {
					t.Fatalf("ws address = %q, want a plain ws:// address", addr)
				}
			}
		})
	}
}

func TestV2RayDialerJLSRejectsUnsupportedNetworks(t *testing.T) {
	for _, network := range []string{"grpc", "h2", "http", "http2", "meek"} {
		s := v2ray.V2Ray{Protocol: "vless", Add: "127.0.0.1", Port: "443", ID: jlsTestUUID, Net: network,
			TLS: "jls", JlsUsername: "u", JlsPassword: "p"}
		if _, _, err := s.Dialer(&dialer.ExtraOption{}, jlsNoopDialer{}); !errors.Is(err, dialer.UnexpectedFieldErr) {
			t.Fatalf("net %v: Dialer() error = %v, want %v", network, err, dialer.UnexpectedFieldErr)
		}
	}
}

func TestV2RayDialerJLSRequiresCredentials(t *testing.T) {
	for _, network := range []string{"tcp", "ws", "httpupgrade"} {
		s := v2ray.V2Ray{Protocol: "vless", Add: "127.0.0.1", Port: "443", ID: jlsTestUUID, Net: network,
			TLS: "jls", JlsUsername: "u"}
		if _, _, err := s.Dialer(&dialer.ExtraOption{}, jlsNoopDialer{}); err == nil {
			t.Fatalf("net %v: Dialer() succeeded without a jls password", network)
		}
	}
}
