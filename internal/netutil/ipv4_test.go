package netutil

import (
	"net"
	"testing"
)

func TestWildcardListenerConflictsWithLocalUpstream(t *testing.T) {
	conflicts, err := ConflictsWithListener(net.IPv4zero, net.IPv4(127, 0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	if !conflicts {
		t.Fatal("wildcard DNS listener must reject a local upstream on the same port")
	}
	conflicts, err = ConflictsWithListener(net.IPv4zero, net.IPv4(8, 8, 8, 8))
	if err != nil {
		t.Fatal(err)
	}
	if conflicts {
		t.Fatal("external upstream was treated as a local listener")
	}
}
