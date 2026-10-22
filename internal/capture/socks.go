package capture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/lihongjie0209/liujian/internal/dnsserver"
	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

type socksResolver struct{ upstream string }

func (r socksResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addresses, err := dnsserver.Resolver(r.upstream).LookupIPAddr(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	if len(addresses) == 0 {
		return ctx, nil, fmt.Errorf("no address for %s", name)
	}
	return ctx, addresses[0].IP, nil
}

func (s *Server) serveSOCKS(listener net.Listener) error {
	server := socks5.NewServer(
		socks5.WithResolver(socksResolver{upstream: s.Config.UpstreamDNS}),
		socks5.WithConnectHandle(s.serveSOCKSConnect),
		socks5.WithBindHandle(rejectSOCKSCommand),
		socks5.WithAssociateHandle(rejectSOCKSCommand),
	)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			if !privateClient(conn.RemoteAddr()) {
				_ = conn.Close()
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			// The request body may be a long-lived HTTP or WebSocket stream.
			// Clear the handshake deadline when the command handler starts.
			err := server.ServeConn(conn)
			if err != nil && s.Log != nil && !errors.Is(err, io.EOF) {
				s.Log.Debug("SOCKS5 connection ended", "error", err)
			}
		}()
	}
}

func privateClient(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && (ip.IsPrivate() || ip.IsLoopback())
}

func rejectSOCKSCommand(_ context.Context, writer io.Writer, _ *socks5.Request) error {
	return socks5.SendReply(writer, statute.RepCommandNotSupported, nil)
}

func (s *Server) serveSOCKSConnect(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	client, ok := writer.(net.Conn)
	if !ok {
		return errors.New("SOCKS5 client connection unavailable")
	}
	_ = client.SetReadDeadline(time.Time{})
	host := request.RawDestAddr.FQDN
	if host == "" {
		host = request.RawDestAddr.IP.String()
	}
	authority := net.JoinHostPort(host, strconv.Itoa(request.RawDestAddr.Port))
	if !s.allowedCapture(host, request.RemoteAddr.String()) {
		return s.tunnelSOCKS(ctx, client, request.Reader, authority)
	}
	if err := socks5.SendReply(client, statute.RepSuccess, client.LocalAddr()); err != nil {
		return err
	}
	reader := bufio.NewReader(request.Reader)
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	first, err := reader.Peek(1)
	_ = client.SetReadDeadline(time.Time{})
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			// Server-first TCP protocols cannot send until upstream connects.
			return s.relaySOCKS(ctx, client, reader, authority)
		}
		return err
	}
	if first[0] == 0x16 || strings.ContainsRune("GPHODCT", rune(first[0])) {
		s.serveInterceptTunnel(client, reader, host, authority)
		return nil
	}
	// SOCKS5 also carries arbitrary TCP protocols. Forward those unchanged.
	return s.relaySOCKS(ctx, client, reader, authority)
}

func (s *Server) tunnelSOCKS(ctx context.Context, client net.Conn, reader io.Reader, authority string) error {
	upstream, err := (&net.Dialer{Timeout: 10 * time.Second, Resolver: dnsserver.Resolver(s.Config.UpstreamDNS)}).DialContext(ctx, "tcp", authority)
	if err != nil {
		_ = socks5.SendReply(client, statute.RepHostUnreachable, nil)
		return err
	}
	defer upstream.Close()
	if err := socks5.SendReply(client, statute.RepSuccess, upstream.LocalAddr()); err != nil {
		return err
	}
	return relayTCP(client, reader, upstream)
}

func (s *Server) relaySOCKS(ctx context.Context, client net.Conn, reader io.Reader, authority string) error {
	upstream, err := (&net.Dialer{Timeout: 10 * time.Second, Resolver: dnsserver.Resolver(s.Config.UpstreamDNS)}).DialContext(ctx, "tcp", authority)
	if err != nil {
		return err
	}
	defer upstream.Close()
	return relayTCP(client, reader, upstream)
}

func relayTCP(client net.Conn, reader io.Reader, upstream net.Conn) error {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, reader)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, err := io.Copy(client, upstream)
	_ = client.SetReadDeadline(time.Now())
	<-done
	return err
}
