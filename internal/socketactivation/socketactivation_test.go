package socketactivation

import (
	"net"
	"testing"
)

type stubListener struct {
	net.Listener
	name    string
	network string
}

func TestListenerByNameFromDoesNotReturnWrongNamedSingleListener(t *testing.T) {
	ipc := stubListener{name: "ipc"}
	if got, ok := listenerByNameFrom([]Listener{{Name: "explorer-events", Listener: ipc}}, "sftp"); ok || got != nil {
		t.Fatalf("got listener for wrong fd name: ok=%v listener=%v", ok, got)
	}
}

func TestListenerByNameFromDoesNotFallbackWhenNameRequested(t *testing.T) {
	sftp := stubListener{name: "sftp"}
	if got, ok := listenerByNameFrom([]Listener{{Listener: sftp}}, "sftp"); ok || got != nil {
		t.Fatalf("got unnamed listener for named lookup: ok=%v listener=%v", ok, got)
	}
}

func TestListenerByNameFromFallsBackWhenNoNameRequested(t *testing.T) {
	sftp := stubListener{name: "sftp"}
	got, ok := listenerByNameFrom([]Listener{{Listener: sftp}})
	if !ok || got != sftp {
		t.Fatalf("fallback listener = (%v, %v), want single listener", got, ok)
	}
}

func TestListenerByNameOrIndexFromFallsBackToUnnamedIndex(t *testing.T) {
	sftp := stubListener{name: "sftp"}
	events := stubListener{name: "events"}
	got, ok := listenerByNameOrIndexFrom([]Listener{{Listener: sftp}, {Listener: events}}, "explorer-events", 1)
	if !ok || got != events {
		t.Fatalf("index fallback listener = (%v, %v), want events", got, ok)
	}
}

func TestListenerByNameOrIndexFromDoesNotFallbackToNamedWrongIndex(t *testing.T) {
	ipc := stubListener{name: "ipc"}
	if got, ok := listenerByNameOrIndexFrom([]Listener{{Name: "explorer-events", Listener: ipc}}, "sftp", 0); ok || got != nil {
		t.Fatalf("got fallback listener for named wrong fd: ok=%v listener=%v", ok, got)
	}
}

func TestListenerByNameOrIndexFromPrefersName(t *testing.T) {
	unnamed := stubListener{name: "unnamed"}
	explorer := stubListener{name: "explorer"}
	got, ok := listenerByNameOrIndexFrom([]Listener{{Listener: unnamed}, {Name: "explorer", Listener: explorer}}, "explorer", 0)
	if !ok || got != explorer {
		t.Fatalf("named listener = (%v, %v), want explorer", got, ok)
	}
}

func TestListenerByNameOrNetworkFromFallsBackToUnnamedNetwork(t *testing.T) {
	sftp := stubListener{name: "sftp", network: "tcp"}
	events := stubListener{name: "events", network: "unix"}
	got, ok := listenerByNameOrNetworkFrom([]Listener{{Listener: sftp}, {Listener: events}}, "explorer-events", "unix")
	if !ok || got != events {
		t.Fatalf("network fallback listener = (%v, %v), want events", got, ok)
	}
}

func TestListenerByNameOrNetworkFromDoesNotFallbackToNamedWrongNetwork(t *testing.T) {
	ipc := stubListener{name: "ipc", network: "unix"}
	if got, ok := listenerByNameOrNetworkFrom([]Listener{{Name: "explorer-events", Listener: ipc}}, "sftp", "unix"); ok || got != nil {
		t.Fatalf("got fallback listener for named wrong fd: ok=%v listener=%v", ok, got)
	}
}

func TestListenerByNameOrNetworkFromRejectsAmbiguousUnnamedNetwork(t *testing.T) {
	a := stubListener{name: "a", network: "tcp"}
	b := stubListener{name: "b", network: "tcp"}
	if got, ok := listenerByNameOrNetworkFrom([]Listener{{Listener: a}, {Listener: b}}, "sftp", "tcp"); ok || got != nil {
		t.Fatalf("got ambiguous network fallback: ok=%v listener=%v", ok, got)
	}
}

func TestListenerByNameOrNetworkFromPrefersName(t *testing.T) {
	unnamed := stubListener{name: "unnamed", network: "tcp"}
	explorer := stubListener{name: "explorer", network: "tcp"}
	got, ok := listenerByNameOrNetworkFrom([]Listener{{Listener: unnamed}, {Name: "explorer", Listener: explorer}}, "explorer", "tcp")
	if !ok || got != explorer {
		t.Fatalf("named listener = (%v, %v), want explorer", got, ok)
	}
}

func (l stubListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l stubListener) Close() error              { return nil }
func (l stubListener) Addr() net.Addr {
	network := l.network
	if network == "" {
		network = "stub"
	}
	return stubAddr{network: network, value: l.name}
}

type stubAddr struct {
	network string
	value   string
}

func (a stubAddr) Network() string { return a.network }
func (a stubAddr) String() string  { return a.value }
