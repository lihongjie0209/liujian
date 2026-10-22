package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lihongjie0209/liujian/internal/ca"
	"github.com/lihongjie0209/liujian/internal/replay"
	"github.com/lihongjie0209/liujian/internal/store"
	"github.com/spf13/cobra"
)

func newCACreateCommand(dataDir *string) *cobra.Command {
	return &cobra.Command{Use: "create", Short: "Create a fresh local CA without replacing an existing one", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := ca.Create(*dataDir); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), filepath.Join(*dataDir, "ca.pem"))
		return nil
	}}
}

func newCADiagnoseCommand(selectCA func() (*ca.Manager, error)) *cobra.Command {
	var connectTo string
	cmd := &cobra.Command{Use: "diagnose HOST[:PORT]", Short: "Inspect local CA and upstream TLS certificate", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		manager, err := selectCA()
		if err != nil {
			return err
		}
		host, port := args[0], "443"
		if h, p, splitErr := net.SplitHostPort(args[0]); splitErr == nil {
			host, port = h, p
		}
		if host == "" || strings.ContainsAny(host, "/ ") {
			return fmt.Errorf("invalid host %q", host)
		}
		root := manager.Root()
		compromised, err := ca.IsCompromisedIssuer(root)
		if err != nil {
			return err
		}
		fingerprint := sha256.Sum256(root.Raw)
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "Local CA: %s\nSHA-256: %s\nValid: %s to %s\nPublicly compromised test key: %t\n", root.Subject, hex.EncodeToString(fingerprint[:]), root.NotBefore.Format(time.RFC3339), root.NotAfter.Format(time.RFC3339), compromised)
		leaf, err := manager.Certificate(host)
		if err != nil {
			return fmt.Errorf("issue local leaf: %w", err)
		}
		fmt.Fprintf(out, "Issued leaf: %s; SAN DNS=%v IP=%v; expires %s\n", leaf.Leaf.Subject, leaf.Leaf.DNSNames, leaf.Leaf.IPAddresses, leaf.Leaf.NotAfter.Format(time.RFC3339))
		address := net.JoinHostPort(host, port)
		if connectTo != "" {
			address = connectTo
		}
		// Fetch the peer chain even when it is untrusted, then verify it explicitly.
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, InsecureSkipVerify: true})
		if err != nil {
			return fmt.Errorf("upstream TLS handshake: %w", err)
		}
		defer conn.Close()
		state := conn.ConnectionState()
		fmt.Fprintf(out, "Upstream TLS: %s; ALPN: %s\n", tls.VersionName(state.Version), state.NegotiatedProtocol)
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("upstream sent no certificate")
		}
		for i, cert := range state.PeerCertificates {
			fmt.Fprintf(out, "Chain[%d]: subject=%s; issuer=%s; expires=%s\n", i, cert.Subject, cert.Issuer, cert.NotAfter.Format(time.RFC3339))
		}
		intermediates := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
		_, err = state.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates})
		if err != nil {
			fmt.Fprintf(out, "System trust: failed: %v\n", err)
		} else {
			fmt.Fprintln(out, "System trust: verified")
		}
		fmt.Fprintln(out, "Revocation checks and certificate pinning are outside this diagnostic.")
		return nil
	}}
	cmd.Flags().StringVar(&connectTo, "connect-to", "", "connect to this IP:port while verifying the requested host")
	return cmd
}

func sessionID(text string) (int64, error) {
	id, err := strconv.ParseInt(text, 10, 64)
	if err != nil || id < 1 {
		return 0, fmt.Errorf("invalid session ID %q", text)
	}
	return id, nil
}

func newReplayCommand(dataDir *string) *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{Use: "replay ID", Short: "Resend a captured HTTP request", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		id, err := sessionID(args[0])
		if err != nil {
			return err
		}
		db, err := store.Open(*dataDir, 0)
		if err != nil {
			return err
		}
		defer db.Close()
		result, err := replay.Send(cmd.Context(), db, id, timeout)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "session=%d status=%d url=%s\n", result.ID, result.Status, result.URL)
		return nil
	}}
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")
	return cmd
}

func newCurlCommand(dataDir *string) *cobra.Command {
	return &cobra.Command{Use: "curl ID", Short: "Print a captured request as a POSIX curl command", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		id, err := sessionID(args[0])
		if err != nil {
			return err
		}
		db, err := store.Open(*dataDir, 0)
		if err != nil {
			return err
		}
		defer db.Close()
		v, err := db.Get(id)
		if err != nil {
			return err
		}
		line, err := replay.Curl(v)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), line)
		return nil
	}}
}
