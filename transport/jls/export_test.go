package jls

// StartJLSServer exposes the jls-tls test server to the external e2e tests.
var StartJLSServer = startJLSServerWith

const (
	TestUsername   = testUsername
	TestPassword   = testPassword
	TestServerName = testServerName
)

func (r serverResult) Err() error { return r.err }
