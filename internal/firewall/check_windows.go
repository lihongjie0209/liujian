//go:build windows

package firewall

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

const checkScript = `$ErrorActionPreference = 'Stop'
$profiles = @(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $true })
if ($profiles.Count -eq 0) { 'disabled'; exit }
$rules = @(Get-NetFirewallApplicationFilter -Program $env:CA_PROXY_FIREWALL_PROGRAM -ErrorAction SilentlyContinue | Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' })
if (@($rules | Where-Object { $_.Action -eq 'Block' }).Count -gt 0) { 'blocked'; exit }
if (@($rules | Where-Object { $_.Action -eq 'Allow' -and ($_.Profile -eq 'Any' -or $_.Profile -match 'Public') }).Count -gt 0) { 'allowed'; exit }
'unknown'`

func Check(ctx context.Context) Status {
	program, err := os.Executable()
	if err != nil {
		return Status{Message: "Cannot locate program for firewall check"}
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", checkScript)
	cmd.Env = append(os.Environ(), "CA_PROXY_FIREWALL_PROGRAM="+program)
	output, err := cmd.Output()
	if err != nil {
		return Status{Message: "Windows firewall check failed; verify phone connectivity"}
	}
	switch strings.TrimSpace(string(output)) {
	case "disabled":
		return Status{Message: "Windows firewall is disabled", OK: true}
	case "allowed":
		return Status{Message: "Windows firewall allows this program", OK: true}
	case "blocked":
		return Status{Message: "Windows firewall has a blocking rule for this program"}
	default:
		return Status{Message: "No program allow rule found; phone access is unverified"}
	}
}
