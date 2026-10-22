package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lihongjie0209/liujian/internal/allowlist"
	"github.com/lihongjie0209/liujian/internal/ca"
	"github.com/lihongjie0209/liujian/internal/capture"
	"github.com/lihongjie0209/liujian/internal/dnsserver"
	"github.com/lihongjie0209/liujian/internal/headless"
	"github.com/lihongjie0209/liujian/internal/netutil"
	"github.com/lihongjie0209/liujian/internal/scripts"
	"github.com/lihongjie0209/liujian/internal/store"
	"github.com/lihongjie0209/liujian/internal/tui"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "liujian:", err)
		os.Exit(1)
	}
}

func rootCommand() *cobra.Command {
	root := &cobra.Command{Use: "liujian", Short: "CLI HTTP/HTTPS capture proxy with DNS interception", SilenceUsage: true, SilenceErrors: true}
	dataDir := defaultDataDir()
	caProfile := ca.DefaultProfile
	root.PersistentFlags().StringVar(&dataDir, "data-dir", dataDir, "directory for CA and captured sessions")
	root.PersistentFlags().StringVar(&caProfile, "ca-profile", caProfile, "embedded CA profile; explicitly setting this overrides an imported CA")
	selectCA := func() (*ca.Manager, error) {
		return ca.Select(dataDir, caProfile, root.PersistentFlags().Changed("ca-profile"))
	}
	root.AddCommand(runCommand(&dataDir, selectCA), caCommand(&dataDir, selectCA), sessionsCommand(&dataDir))
	return root
}

func defaultDataDir() string {
	if path := os.Getenv("XDG_DATA_HOME"); path != "" {
		return filepath.Join(path, "ca-proxy")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./ca-proxy-data"
	}
	return filepath.Join(home, ".local", "share", "ca-proxy")
}

func runCommand(dataDir *string, selectCA func() (*ca.Manager, error)) *cobra.Command {
	var ipText, upstream string
	var exclude, dnsAnswerRules, allowHostRaw, allowClientRaw []string
	var httpExtraPorts, httpsExtraPorts []int
	var noTUI, headlessMode bool
	var outputFormat, bodyDir, captureLog, scriptConfig string
	var inlineBodyBytes int
	var dnsPort, httpPort, httpsPort, proxyPort int
	var bodyMB, frameMB, diskMB int64
	cmd := &cobra.Command{Use: "run", Short: "Start DNS, transparent HTTP/HTTPS, and explicit proxy", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if outputFormat == "jsonline" {
			outputFormat = "jsonl"
		}
		out := &headless.Output{Writer: cmd.OutOrStdout(), Format: outputFormat, BodyDir: bodyDir, InlineBytes: inlineBodyBytes}
		if err := out.Validate(); err != nil {
			return err
		}
		useHeadless := noTUI || headlessMode || cmd.Flags().Changed("output")
		if useHeadless && captureLog != "" {
			return errors.New("--capture-log requires TUI mode; use --output jsonl for headless capture")
		}
		if out.BodyDir == "" {
			out.BodyDir = filepath.Join(*dataDir, "bodies")
		}
		ip := net.ParseIP(ipText)
		if ip == nil || ip.To4() == nil {
			return errors.New("--listen-ip must be an IPv4 address")
		}
		if bodyMB < 1 || bodyMB > 1024 || frameMB < 1 || frameMB > 1024 || diskMB < 1 || diskMB > 1048576 {
			return errors.New("body-mb, frame-mb, and disk-mb must be positive and within supported limits")
		}
		if upstream == "" {
			var err error
			upstream, err = systemDNS()
			if err != nil {
				return err
			}
		}
		if !strings.Contains(upstream, ":") {
			upstream = net.JoinHostPort(upstream, "53")
		}
		uHost, uPort, err := net.SplitHostPort(upstream)
		if err != nil {
			return fmt.Errorf("--upstream-dns: %w", err)
		}
		if net.ParseIP(uHost) == nil {
			return errors.New("--upstream-dns must use an IP address")
		}
		if uPort == fmt.Sprint(dnsPort) {
			conflicts, err := netutil.ConflictsWithListener(ip, net.ParseIP(uHost))
			if err != nil {
				return err
			}
			if conflicts {
				return errors.New("upstream DNS must differ from capture listener")
			}
		}
		answerRules, err := dnsserver.ParseAnswerRules(dnsAnswerRules)
		if err != nil {
			return err
		}
		allowHosts, err := allowlist.ParseHosts(allowHostRaw)
		if err != nil {
			return err
		}
		allowClients, err := allowlist.ParseClients(allowClientRaw)
		if err != nil {
			return err
		}
		lanIPs, err := netutil.LocalPrivateIPv4()
		if err != nil {
			return err
		}
		phoneIPs := make([]string, 0, len(lanIPs))
		for _, lanIP := range lanIPs {
			phoneIPs = append(phoneIPs, lanIP.String())
		}
		manager, err := selectCA()
		if err != nil {
			return err
		}
		var scriptRunner *scripts.Runner
		if scriptConfig != "" {
			scriptRunner, err = scripts.Load(scriptConfig)
			if err != nil {
				return err
			}
		}
		caCompromised, err := ca.IsCompromisedIssuer(manager.Root())
		if err != nil {
			return err
		}
		db, err := store.Open(*dataDir, diskMB<<20)
		if err != nil {
			return err
		}
		defer db.Close()
		logOutput := os.Stderr
		if !useHeadless {
			logFile, err := os.OpenFile(filepath.Join(*dataDir, "ca-proxy.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				return fmt.Errorf("open capture log: %w", err)
			}
			defer logFile.Close()
			logOutput = logFile
		}
		logger := slog.New(slog.NewTextHandler(logOutput, nil))
		server := &capture.Server{Config: capture.Config{ListenIP: ip, UpstreamDNS: upstream, Exclude: exclude, AllowHosts: allowHosts, AllowClients: allowClients, DNSAnswerRules: answerRules, DNSPort: dnsPort, HTTPPort: httpPort, HTTPSPort: httpsPort, HTTPExtraPorts: httpExtraPorts, HTTPSExtraPorts: httpsExtraPorts, ProxyPort: proxyPort, BodyLimit: bodyMB << 20, FrameLimit: frameMB << 20}, CA: manager, Store: db, Scripts: scriptRunner, Log: logger}
		var lastSession, lastMessage int64
		var auditOut *headless.Output
		if useHeadless || captureLog != "" {
			lastSession, lastMessage, err = db.LatestIDs()
			if err != nil {
				return err
			}
		}
		if captureLog != "" {
			if err := os.MkdirAll(filepath.Dir(captureLog), 0o700); err != nil {
				return fmt.Errorf("create capture log directory: %w", err)
			}
			file, err := os.OpenFile(captureLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				return fmt.Errorf("open capture log: %w", err)
			}
			defer file.Close()
			auditOut = &headless.Output{Writer: file, Format: "jsonl", BodyDir: out.BodyDir, InlineBytes: out.InlineBytes}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		errorsCh := make(chan error, 1)
		go func() { errorsCh <- server.Run(ctx) }()
		var auditCh chan error
		if auditOut != nil {
			auditCh = make(chan error, 1)
			go func() { auditCh <- followStore(ctx, db, auditOut, lastSession, lastMessage) }()
		}
		if ip.IsUnspecified() {
			fmt.Fprintf(os.Stderr, "Listening on all IPv4 interfaces; set phone DNS to a reachable LAN address: %s\n", strings.Join(phoneIPs, ", "))
		} else {
			fmt.Fprintf(os.Stderr, "Set phone DNS to %s\n", ip)
		}
		fmt.Fprintln(os.Stderr, "CA: http://ca-proxy.test/ca.crt")
		if caCompromised {
			fmt.Fprintln(os.Stderr, "CA status: publicly compromised test key; current clients may reject its certificates.")
		}
		fmt.Fprintln(os.Stderr, "DNS mode may interrupt unconfigured ports and QUIC; use --exclude for affected domains.")
		if useHeadless {
			return streamUntilDone(ctx, db, errorsCh, out, lastSession, lastMessage)
		}
		if captureLog != "" {
			fmt.Fprintln(os.Stderr, "Capture JSONL:", captureLog)
		}
		uiCh := make(chan error, 1)
		listeners := &tui.Listeners{
			IP: ip.String(), DNSPort: dnsPort, PhoneIPs: phoneIPs,
			AllowHosts: append([]string(nil), allowHostRaw...), AllowClients: append([]string(nil), allowClientRaw...),
			CACompromised:   caCompromised,
			DNSAnswerRules:  dnsAnswerRules,
			TLSFailureCount: server.TLSFailureCount,
			HTTPPorts:       append([]int{httpPort}, httpExtraPorts...),
			HTTPSPorts:      append([]int{httpsPort}, httpsExtraPorts...),
			ProxyPort:       proxyPort,
		}
		go func() { uiCh <- tui.Run(ctx, db, listeners) }()
		select {
		case err := <-errorsCh:
			cancel()
			<-uiCh
			return errors.Join(err, waitAudit(auditCh))
		case err := <-uiCh:
			cancel()
			<-errorsCh
			return errors.Join(err, waitAudit(auditCh))
		case err := <-auditCh:
			cancel()
			<-uiCh
			<-errorsCh
			return err
		}
	}}
	cmd.Flags().StringVar(&ipText, "listen-ip", "0.0.0.0", "IPv4 address to bind (default: all interfaces)")
	cmd.Flags().StringVar(&upstream, "upstream-dns", "", "independent upstream DNS IP[:port] (default: system resolver)")
	cmd.Flags().StringSliceVar(&exclude, "exclude", nil, "domain or *.domain passed through unchanged")
	cmd.Flags().StringSliceVar(&allowHostRaw, "allow-host", nil, "capture only target domains, *.domains, IPs, or CIDRs (repeatable)")
	cmd.Flags().StringSliceVar(&allowClientRaw, "allow-client", nil, "capture only clients with these IPs or CIDRs (repeatable)")
	cmd.Flags().StringSliceVar(&dnsAnswerRules, "dns-answer-rule", nil, "map DNS client CIDR to local IPv4 answer (repeatable: CIDR=IP)")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "alias for --headless")
	cmd.Flags().BoolVar(&headlessMode, "headless", false, "stream captured sessions and messages without a TUI")
	cmd.Flags().StringVar(&outputFormat, "output", "console", "headless output format: console or jsonl")
	cmd.Flags().IntVar(&inlineBodyBytes, "inline-body-bytes", 4096, "write larger captured bodies to separate files")
	cmd.Flags().StringVar(&bodyDir, "body-dir", "", "directory for large headless bodies (default: DATA_DIR/bodies)")
	cmd.Flags().StringVar(&captureLog, "capture-log", "", "write live sessions and messages as JSON Lines while TUI runs")
	cmd.Flags().StringVar(&scriptConfig, "script-config", "", "JSON config for ordered request/response scripts")
	cmd.Flags().IntVar(&dnsPort, "dns-port", 53, "DNS UDP/TCP port")
	cmd.Flags().IntVar(&httpPort, "http-port", 80, "transparent HTTP port")
	cmd.Flags().IntVar(&httpsPort, "https-port", 443, "transparent HTTPS port")
	cmd.Flags().IntSliceVar(&httpExtraPorts, "http-extra-ports", nil, "additional DNS-mode HTTP ports (comma-separated or repeatable)")
	cmd.Flags().IntSliceVar(&httpsExtraPorts, "https-extra-ports", nil, "additional DNS-mode HTTPS ports (comma-separated or repeatable)")
	cmd.Flags().IntVar(&proxyPort, "proxy-port", 8080, "explicit HTTP proxy port")
	cmd.Flags().Int64Var(&bodyMB, "body-mb", 10, "maximum stored bytes per request or response body (MiB)")
	cmd.Flags().Int64Var(&frameMB, "frame-mb", 1, "maximum stored bytes per WebSocket message (MiB)")
	cmd.Flags().Int64Var(&diskMB, "disk-mb", 1024, "maximum stored session payload size (MiB)")
	return cmd
}

func systemDNS() (string, error) {
	c, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("read /etc/resolv.conf: %w; set --upstream-dns", err)
	}
	if len(c.Servers) == 0 {
		return "", errors.New("no system DNS server; set --upstream-dns")
	}
	return net.JoinHostPort(c.Servers[0], c.Port), nil
}

func streamUntilDone(ctx context.Context, db *store.Store, errCh <-chan error, out *headless.Output, lastSession, lastMessage int64) error {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-errCh:
			if flushErr := streamNew(db, out, &lastSession, &lastMessage); flushErr != nil {
				return flushErr
			}
			return err
		case <-ctx.Done():
			err := <-errCh
			if flushErr := streamNew(db, out, &lastSession, &lastMessage); flushErr != nil {
				return flushErr
			}
			return err
		case <-tick.C:
			if err := streamNew(db, out, &lastSession, &lastMessage); err != nil {
				return err
			}
		}
	}
}

func followStore(ctx context.Context, db *store.Store, out *headless.Output, lastSession, lastMessage int64) error {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return streamNew(db, out, &lastSession, &lastMessage)
		case <-tick.C:
			if err := streamNew(db, out, &lastSession, &lastMessage); err != nil {
				return err
			}
		}
	}
}

func waitAudit(ch <-chan error) error {
	if ch == nil {
		return nil
	}
	return <-ch
}

func streamNew(db *store.Store, out *headless.Output, lastSession, lastMessage *int64) error {
	for {
		ids, err := db.IDsAfter(*lastSession, 500)
		if err != nil {
			return err
		}
		for _, id := range ids {
			v, err := db.Get(id)
			if err != nil {
				return err
			}
			if err := out.WriteSession(v); err != nil {
				return err
			}
			*lastSession = id
		}
		if len(ids) < 500 {
			break
		}
	}
	for {
		messages, err := db.MessagesAfter(*lastMessage, 500)
		if err != nil {
			return err
		}
		for _, message := range messages {
			if err := out.WriteMessage(message); err != nil {
				return err
			}
			*lastMessage = message.ID
		}
		if len(messages) < 500 {
			return nil
		}
	}
}

func caCommand(dataDir *string, selectCA func() (*ca.Manager, error)) *cobra.Command {
	root := &cobra.Command{Use: "ca", Short: "Manage the local signing CA"}
	root.AddCommand(&cobra.Command{Use: "import CERT_PEM KEY_PEM", Args: cobra.ExactArgs(2), RunE: func(_ *cobra.Command, args []string) error { return ca.Import(*dataDir, args[0], args[1]) }})
	root.AddCommand(&cobra.Command{Use: "export OUTPUT", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		manager, err := selectCA()
		if err != nil {
			return err
		}
		return manager.Export(args[0])
	}})
	root.AddCommand(&cobra.Command{Use: "profiles", Short: "List embedded test CA profiles", Args: cobra.NoArgs, Run: func(_ *cobra.Command, _ []string) {
		for _, name := range ca.Profiles() {
			fmt.Println(name)
		}
	}})
	return root
}

func sessionsCommand(dataDir *string) *cobra.Command {
	root := &cobra.Command{Use: "sessions", Short: "Browse saved sessions", RunE: func(_ *cobra.Command, _ []string) error {
		db, err := store.Open(*dataDir, 0)
		if err != nil {
			return err
		}
		defer db.Close()
		return tui.Run(context.Background(), db, nil)
	}}
	root.AddCommand(&cobra.Command{Use: "export OUTPUT.har", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		db, err := store.Open(*dataDir, 0)
		if err != nil {
			return err
		}
		defer db.Close()
		return db.ExportHAR(args[0])
	}})
	return root
}
