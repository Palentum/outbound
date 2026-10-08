package anytls

import (
	"io"
	"reflect"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	protocolanytls "github.com/daeuniverse/outbound/protocol/anytls"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/transport/jls"
)

const anytlsJLSLink = "anytls://auth@127.0.0.1:443?security=jls&jls-username=u&jls-password=p&sni=www.example.com#n"

func TestParseAnytlsURLJLS(t *testing.T) {
	s, err := parseAnytlsURL(anytlsJLSLink)
	if err != nil {
		t.Fatalf("parseAnytlsURL() error = %v", err)
	}
	want := &Anytls{link: anytlsJLSLink, Name: "n", Auth: "auth", Host: "127.0.0.1:443", Sni: "www.example.com",
		Security: "jls", JlsUsername: "u", JlsPassword: "p"}
	if !reflect.DeepEqual(s, want) {
		t.Fatalf("parseAnytlsURL() = %+v, want %+v", s, want)
	}
}

func TestDialerJLSReplacesTLS(t *testing.T) {
	d, property, err := NewAnytls(&dialer.ExtraOption{}, direct.SymmetricDirect, anytlsJLSLink)
	if err != nil {
		t.Fatalf("NewAnytls() error = %v", err)
	}
	defer d.(io.Closer).Close()
	if property.Link != anytlsJLSLink {
		t.Fatalf("property link = %q, want %q", property.Link, anytlsJLSLink)
	}

	protocolDialer, ok := d.(*protocolanytls.Dialer)
	if !ok {
		t.Fatalf("NewAnytls() returned %T, want *protocolanytls.Dialer", d)
	}
	if tlsConfig := reflect.ValueOf(protocolDialer).Elem().FieldByName("tlsConfig"); !tlsConfig.IsNil() {
		t.Fatal("protocol dialer keeps a tls.Config although jls secures the session")
	}
	j, ok := protocolDialer.UnwrapDialer().(*jls.JLS)
	if !ok {
		t.Fatalf("next dialer = %T, want *jls.JLS", protocolDialer.UnwrapDialer())
	}
	if got := reflect.ValueOf(j).Elem().FieldByName("serverName").String(); got != "www.example.com" {
		t.Fatalf("jls server name = %q, want www.example.com", got)
	}
}

func TestDialerJLSRequiresCredentials(t *testing.T) {
	for _, link := range []string{
		"anytls://auth@127.0.0.1:443?security=jls&jls-password=p",
		"anytls://auth@127.0.0.1:443?security=jls&jls-username=u",
	} {
		if _, _, err := NewAnytls(&dialer.ExtraOption{}, direct.SymmetricDirect, link); err == nil {
			t.Fatalf("NewAnytls(%q) succeeded without jls credentials", link)
		}
	}
}
