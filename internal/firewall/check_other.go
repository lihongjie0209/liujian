//go:build !windows

package firewall

import "context"

func Check(context.Context) Status {
	return Status{Message: "Firewall access is unverified; check from the phone"}
}
