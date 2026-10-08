package trojan

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/trojanc"
	"github.com/daeuniverse/outbound/transport/jls"
)

type noopDialer struct{}

func (noopDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, errors.New("noop dialer")
}

// jlsLayer returns the JLS dialer found by unwrapping d.
func jlsLayer(t *testing.T, d netproxy.Dialer) reflect.Value {
	t.Helper()
	for d != nil {
		if j, ok := d.(*jls.JLS); ok {
			return reflect.ValueOf(j).Elem()
		}
		u, ok := d.(interface{ UnwrapDialer() netproxy.Dialer })
		if !ok {
			break
		}
		d = u.UnwrapDialer()
	}
	t.Fatal("no JLS layer in the dialer chain")
	return reflect.Value{}
}

func jlsALPN(j reflect.Value) []string {
	alpn := j.FieldByName("alpn")
	out := make([]string, alpn.Len())
	for i := range out {
		out[i] = alpn.Index(i).String()
	}
	return out
}

func TestParseTrojanURLJLS(t *testing.T) {
	tests := []struct {
		link string
		want *Trojan
	}{
		{
			link: "trojan://pw@127.0.0.1:443?security=jls&jls-username=u&jls-password=p&sni=www.example.com#n",
			want: &Trojan{Name: "n", Server: "127.0.0.1", Port: 443, Password: "pw", Sni: "www.example.com",
				Security: "jls", JlsUsername: "u", JlsPassword: "p", Protocol: "trojan"},
		},
		{
			link: "trojan-go://pw@127.0.0.1:443?type=ws&path=%2Fws&host=cdn.example.com&security=jls&jls-username=u&jls-password=p#n",
			want: &Trojan{Name: "n", Server: "127.0.0.1", Port: 443, Password: "pw", Sni: "127.0.0.1",
				Type: "ws", Host: "cdn.example.com", Path: "/ws",
				Security: "jls", JlsUsername: "u", JlsPassword: "p", Protocol: "trojan-go"},
		},
	}
	for _, tt := range tests {
		s, err := ParseTrojanURL(tt.link)
		if err != nil {
			t.Fatalf("ParseTrojanURL(%q) failed: %v", tt.link, err)
		}
		if !reflect.DeepEqual(s, tt.want) {
			t.Fatalf("ParseTrojanURL(%q) = %+v, want %+v", tt.link, s, tt.want)
		}
		again, err := ParseTrojanURL(s.ExportToURL())
		if err != nil {
			t.Fatalf("ParseTrojanURL(export) failed: %v", err)
		}
		if !reflect.DeepEqual(again, s) {
			t.Fatalf("export round trip = %+v, want %+v", again, s)
		}
	}
}

func TestTrojanDialerJLS(t *testing.T) {
	tests := []struct {
		typ      string
		wantALPN []string
	}{
		{"", []string{}},
		{"ws", []string{"http/1.1"}},
		{"httpupgrade", []string{"http/1.1"}},
	}
	for _, tt := range tests {
		t.Run("type="+tt.typ, func(t *testing.T) {
			s := &Trojan{Server: "127.0.0.1", Port: 443, Password: "pw", Sni: "www.example.com", Type: tt.typ,
				Security: "jls", JlsUsername: "u", JlsPassword: "p", Protocol: "trojan-go"}
			d, _, err := s.Dialer(&dialer.ExtraOption{}, noopDialer{})
			if err != nil {
				t.Fatalf("dialer creation failed: %v", err)
			}
			j := jlsLayer(t, d)
			if got := j.FieldByName("serverName").String(); got != "www.example.com" {
				t.Fatalf("server name = %q, want www.example.com", got)
			}
			if got := jlsALPN(j); !slices.Equal(got, tt.wantALPN) {
				t.Fatalf("alpn = %q, want %q", got, tt.wantALPN)
			}
		})
	}
}

func TestTrojanDialerJLSRejectsGrpc(t *testing.T) {
	s := &Trojan{Server: "127.0.0.1", Port: 443, Password: "pw", Sni: "www.example.com", Type: "grpc",
		Security: "jls", JlsUsername: "u", JlsPassword: "p", Protocol: "trojan-go"}
	if _, _, err := s.Dialer(&dialer.ExtraOption{}, noopDialer{}); !errors.Is(err, dialer.UnexpectedFieldErr) {
		t.Fatalf("Dialer() error = %v, want %v", err, dialer.UnexpectedFieldErr)
	}
}

func TestTrojanDialerJLSRequiresCredentials(t *testing.T) {
	for _, link := range []string{
		"trojan://pw@127.0.0.1:443?security=jls&jls-password=p",
		"trojan://pw@127.0.0.1:443?security=jls&jls-username=u",
	} {
		if _, _, err := NewTrojan(&dialer.ExtraOption{}, noopDialer{}, link); err == nil {
			t.Fatalf("NewTrojan(%q) succeeded without jls credentials", link)
		}
	}
}

func TestParseTrojanURLKeepsNonJLSExportUnchanged(t *testing.T) {
	s, err := ParseTrojanURL("trojan://pw@127.0.0.1:443?security=tls&jls-username=u&jls-password=p&sni=www.example.com#n")
	if err != nil {
		t.Fatalf("ParseTrojanURL failed: %v", err)
	}
	if s.Security != "" || s.JlsUsername != "" || s.JlsPassword != "" {
		t.Fatalf("non-jls link kept jls fields: %+v", s)
	}
	if link := s.ExportToURL(); strings.Contains(link, "security") || strings.Contains(link, "jls") {
		t.Fatalf("non-jls export = %q, want no security or jls params", link)
	}
}
