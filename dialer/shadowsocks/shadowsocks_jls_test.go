package shadowsocks

import (
	"encoding/base64"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/transport/jls"
)

func ssJLSLink(plugin string) string {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:ss-password"))
	return "ss://" + userinfo + "@127.0.0.1:443/?plugin=" + url.QueryEscape(plugin) + "#jls"
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

func TestParseSSURLJLSPlugin(t *testing.T) {
	s, err := ParseSSURL(ssJLSLink("jls;host=www.example.com;username=u;password=p;alpn=h2,http/1.1"))
	if err != nil {
		t.Fatalf("ParseSSURL failed: %v", err)
	}
	want := Sip003{Name: "jls", Opts: Sip003Opts{
		Host:     "www.example.com",
		Username: "u",
		Password: "p",
		Alpn:     "h2,http/1.1",
	}}
	if !reflect.DeepEqual(s.Plugin, want) {
		t.Fatalf("plugin = %+v, want %+v", s.Plugin, want)
	}
	if s.UDP {
		t.Fatal("expected UDP to be disabled with the jls plugin")
	}

	again, err := ParseSSURL(s.ExportToURL())
	if err != nil {
		t.Fatalf("ParseSSURL(export) failed: %v", err)
	}
	if !reflect.DeepEqual(again, s) {
		t.Fatalf("export round trip = %+v, want %+v", again, s)
	}
}

func TestParseSip003JLSAliases(t *testing.T) {
	plugin := ParseSip003("JLS;iv=u;passwd=p;sni=sni.example.com")
	want := Sip003{Name: "jls", Opts: Sip003Opts{
		Username: "u",
		Password: "p",
		SNI:      "sni.example.com",
	}}
	if !reflect.DeepEqual(plugin, want) {
		t.Fatalf("plugin = %+v, want %+v", plugin, want)
	}
}

func TestShadowsocksDialerWithJLSPlugin(t *testing.T) {
	tests := []struct {
		plugin         string
		wantServerName string
		wantALPN       []string
	}{
		{"jls;host=www.example.com;username=u;password=p;alpn=h2,http/1.1", "www.example.com", []string{"h2", "http/1.1"}},
		{"jls;host=www.example.com;sni=sni.example.com;username=u;password=p", "sni.example.com", []string{}},
		{"jls;username=u;password=p", "127.0.0.1", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.plugin, func(t *testing.T) {
			s, err := ParseSSURL(ssJLSLink(tt.plugin))
			if err != nil {
				t.Fatalf("ParseSSURL failed: %v", err)
			}
			d, property, err := s.Dialer(&dialer.ExtraOption{}, noopDialer{})
			if err != nil {
				t.Fatalf("dialer creation failed: %v", err)
			}
			if !strings.Contains(property.Link, "plugin=jls") {
				t.Fatalf("unexpected exported link: %q", property.Link)
			}
			j := jlsLayer(t, d)
			if got := j.FieldByName("serverName").String(); got != tt.wantServerName {
				t.Fatalf("server name = %q, want %q", got, tt.wantServerName)
			}
			if got := j.FieldByName("user").FieldByName("username").String(); got != "u" {
				t.Fatalf("username = %q, want u", got)
			}
			if got := jlsALPN(j); !slices.Equal(got, tt.wantALPN) {
				t.Fatalf("alpn = %q, want %q", got, tt.wantALPN)
			}
		})
	}
}

func TestShadowsocksDialerJLSRequiresCredentials(t *testing.T) {
	for _, plugin := range []string{
		"jls;host=www.example.com;password=p",
		"jls;host=www.example.com;username=u",
	} {
		s, err := ParseSSURL(ssJLSLink(plugin))
		if err != nil {
			t.Fatalf("ParseSSURL failed: %v", err)
		}
		if _, _, err := s.Dialer(&dialer.ExtraOption{}, noopDialer{}); err == nil {
			t.Fatalf("plugin %q: dialer creation succeeded without jls credentials", plugin)
		}
	}
}
