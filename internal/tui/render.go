package tui

import (
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/lihongjie0209/liujian/internal/store"
)

const (
	tabHeaders = iota
	tabPayload
	tabPreview
	tabResponse
	tabCookies
	tabTiming
	tabMessages
	tabScripts
)

var detailTabs = []string{"Headers", "Payload", "Preview", "Response", "Cookies", "Timing", "Messages", "Scripts"}

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8AB4F8"))
	mutedStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#9AA0A6"))
	selectedStyle = lipgloss.NewStyle().Background(lipgloss.Color("#25344B")).Foreground(lipgloss.Color("#E8EAED"))
	goodStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#81C995"))
	badStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#F28B82"))
)

func tabCount(v *store.Session) int {
	return len(tabsFor(v))
}

func tabsFor(v *store.Session) []string {
	if v != nil && v.Proto == "TLS" {
		return []string{"Error"}
	}
	tabs := append([]string(nil), detailTabs[:tabMessages]...)
	if hasMessagesTab(v) {
		tabs = append(tabs, "Messages")
	}
	if v != nil && len(v.ScriptRuns) > 0 {
		tabs = append(tabs, "Scripts")
	}
	return tabs
}

func hasMessagesTab(v *store.Session) bool {
	return v != nil && (v.Status == http.StatusSwitchingProtocols || len(v.Messages) > 0 || strings.HasPrefix(strings.ToLower(v.ResponseHeaders.Get("Content-Type")), "text/event-stream"))
}

func (m model) View() string {
	if m.detail && m.item != nil {
		return m.detailView()
	}
	return m.listView()
}

func (m model) listView() string {
	width := max(64, m.width)
	var b strings.Builder
	mode := "HISTORY"
	if m.live {
		mode = "● RECORDING"
	}
	b.WriteString(titleStyle.Render("Network") + "  " + mode + "  " + mutedStyle.Render("↑↓ select  ←→ type  Enter details  / search  q quit") + "\n")
	if m.live {
		for _, line := range m.listenerGuide(width) {
			style := mutedStyle
			if strings.HasPrefix(line, "Firewall") && m.firewall != nil && !m.firewall.OK {
				style = badStyle
			}
			if strings.HasPrefix(line, "CA status") {
				style = badStyle
			}
			b.WriteString(style.Render(line) + "\n")
		}
	}
	filter := "All requests"
	if m.editing {
		filter = "Filter: " + m.filter + "▌"
	} else if m.filter != "" {
		filter = "Filter: " + m.filter
	}
	b.WriteString(filter + "\n")
	b.WriteString(m.kindFilterView() + "\n")
	b.WriteString(mutedStyle.Render("Search: text, req:keyword, resp:keyword, url:... proto:... method:... status:... client:...  0=All") + "\n")
	if m.errorText != "" {
		b.WriteString(badStyle.Render("Error: "+safe(m.errorText)) + "\n")
	}
	b.WriteString(rule(width) + "\n")
	compact := width < 105
	nameWidth := width - 83
	if compact {
		nameWidth = width - 50
	}
	nameWidth = max(18, nameWidth)
	if compact {
		b.WriteString(fmt.Sprintf("  %-*s %-7s %-17s %8s %9s\n", nameWidth, "Name", "Status", "Type", "Size", "Time"))
	} else {
		b.WriteString(fmt.Sprintf("  %-*s %-7s %-17s %-9s %8s %9s %-12s\n", nameWidth, "Name", "Status", "Type", "Initiator", "Size", "Time", "Waterfall"))
	}
	b.WriteString(rule(width) + "\n")
	visible := max(1, m.height-strings.Count(b.String(), "\n")-3)
	start := max(0, m.selected-visible+1)
	end := min(len(m.rows), start+visible)
	maxDuration := time.Duration(0)
	for _, v := range m.rows {
		maxDuration = max(maxDuration, v.Duration)
	}
	var totalBytes int64
	for _, v := range m.rows {
		totalBytes += v.ResponseBytes
	}
	if len(m.rows) == 0 {
		b.WriteString("  No captured requests yet.\n")
	}
	for i := start; i < end; i++ {
		v := m.rows[i]
		name := v.Method + " " + resourceName(v.URL)
		if v.Proto == "TLS" && v.ErrorCount > 1 {
			name += fmt.Sprintf(" ×%d", v.ErrorCount)
		}
		name = clip(name, nameWidth)
		status := statusLabel(v)
		kind := clip(resourceType(v), 17)
		size := humanBytes(v.ResponseBytes)
		if v.ResponseTruncated {
			size = "≥" + size
		}
		row := ""
		statusCell := fmt.Sprintf("%-7s", status)
		if i != m.selected {
			switch {
			case v.Status >= 400 || v.Error != "":
				statusCell = badStyle.Render(statusCell)
			case v.Status >= 200 && v.Status < 300:
				statusCell = goodStyle.Render(statusCell)
			case v.Status >= 300 && v.Status < 400:
				statusCell = titleStyle.Render(statusCell)
			}
		}
		if compact {
			row = fmt.Sprintf("  %-*s ", nameWidth, name) + statusCell + fmt.Sprintf(" %-17s %8s %9s", kind, size, durationLabel(v.Duration))
		} else {
			row = fmt.Sprintf("  %-*s ", nameWidth, name) + statusCell + fmt.Sprintf(" %-17s %-9s %8s %9s %-12s", kind, "—", size, durationLabel(v.Duration), waterfall(v.Duration, maxDuration))
		}
		if i == m.selected {
			row = selectedStyle.Render("›" + row[1:])
		}
		b.WriteString(row + "\n")
	}
	b.WriteString(rule(width) + "\n")
	b.WriteString(fmt.Sprintf("%d requests  •  %s captured body", len(m.rows), humanBytes(totalBytes)))
	if m.live {
		b.WriteString("  •  DNS mode: unconfigured ports and QUIC may fail")
	}
	return b.String()
}

func (m model) kindFilterView() string {
	var b strings.Builder
	for i, option := range kindFilters {
		if i == 7 {
			b.WriteByte('\n')
		}
		label := " " + option.label + " "
		if i == m.selectedKind {
			b.WriteString(selectedStyle.Render(label))
		} else {
			b.WriteString(mutedStyle.Render(label))
		}
	}
	return b.String()
}

func (m model) listenerGuide(width int) []string {
	l := m.listeners
	address := net.JoinHostPort(l.IP, strconv.Itoa(l.DNSPort))
	lines := []string{
		"Listening  DNS UDP/TCP " + address + "  |  HTTP/SOCKS5 proxy " + net.JoinHostPort(l.IP, strconv.Itoa(l.ProxyPort)),
		"           HTTP " + portLabels(l.HTTPPorts) + "  |  HTTPS " + portLabels(l.HTTPSPorts),
	}
	ip := net.ParseIP(l.IP)
	if ip != nil && ip.IsUnspecified() {
		lines = append(lines, "Listening  All IPv4 interfaces (0.0.0.0).")
		if len(l.PhoneIPs) > 0 {
			lines = append(lines, "Phone setup  On the same Wi-Fi, set phone DNS to the reachable LAN IP: "+strings.Join(l.PhoneIPs, ", ")+".")
		} else {
			lines = append(lines, "Phone setup  Set phone DNS to this computer's LAN IPv4 address on the same Wi-Fi.")
		}
	} else if ip == nil || ip.IsLoopback() {
		lines = append(lines, "Phone setup  Listener is local-only; use --listen-ip with this computer's LAN IPv4 address.")
	} else {
		lines = append(lines, "Phone setup  On the same Wi-Fi, set phone DNS to "+l.IP+".")
	}
	if l.DNSPort != 53 {
		lines = append(lines, "Phone setup  Standard phone DNS settings require port 53; restart with --dns-port 53.")
	}
	if l.TLSFailureCount != nil {
		if failures := l.TLSFailureCount(); failures > 0 {
			lines = append(lines, fmt.Sprintf("TLS  %d handshake failures; check CA trust or certificate pinning.", failures))
		}
	}
	if l.CACompromised {
		lines = append(lines, "CA status  Publicly compromised test key; current clients may reject its certificates.")
	}
	if m.firewall == nil {
		lines = append(lines, "Firewall  Checking Windows firewall; refreshes every 15s.")
	} else {
		lines = append(lines, "Firewall  "+m.firewall.Message+" (refreshes every 15s).")
	}
	if len(l.DNSAnswerRules) > 0 {
		lines = append(lines, "DNS answers  Same subnet automatically; explicit rules: "+strings.Join(l.DNSAnswerRules, ", "))
	} else {
		lines = append(lines, "DNS answers  Same subnet automatically; other client networks need --dns-answer-rule CIDR=LOCAL_IP.")
	}
	if len(l.AllowHosts) > 0 || len(l.AllowClients) > 0 {
		if len(l.AllowHosts) > 0 {
			lines = append(lines, "Capture targets  "+strings.Join(l.AllowHosts, ", "))
		}
		if len(l.AllowClients) > 0 {
			lines = append(lines, "Capture clients  "+strings.Join(l.AllowClients, ", "))
		}
	} else {
		lines = append(lines, "Capture scope  All targets and private-network clients; use --allow-host or --allow-client to limit.")
	}
	if len(l.HTTPPorts) > 0 {
		caURL := "http://ca-proxy.test"
		if l.HTTPPorts[0] != 80 {
			caURL += ":" + strconv.Itoa(l.HTTPPorts[0])
		}
		lines = append(lines, "             Open "+caURL+"/ca.crt on the phone and trust the CA certificate.")
	}
	var wrapped []string
	for _, line := range lines {
		wrapped = append(wrapped, wrapGuide(line, width)...)
	}
	return wrapped
}

func portLabels(ports []int) string {
	if len(ports) == 0 {
		return "(none)"
	}
	labels := make([]string, len(ports))
	for i, port := range ports {
		labels[i] = ":" + strconv.Itoa(port)
	}
	return strings.Join(labels, ", ")
}

func wrapGuide(line string, width int) []string {
	words := strings.Fields(line)
	if len(words) == 0 {
		return nil
	}
	limit := max(20, width-2)
	current := words[0]
	var lines []string
	for _, word := range words[1:] {
		if lipgloss.Width(current)+1+lipgloss.Width(word) > limit {
			lines = append(lines, current)
			current = "  " + word
		} else {
			current += " " + word
		}
	}
	return append(lines, current)
}

func (m model) detailView() string {
	v := m.item
	width := max(64, m.width)
	var header strings.Builder
	header.WriteString(titleStyle.Render("← Network") + "  /  " + clip(resourceName(v.URL), width-25) + "  " + statusBadge(v) + "\n")
	header.WriteString(mutedStyle.Render(v.Method+"  "+clip(v.URL, width-12)) + "\n")
	header.WriteString(rule(width) + "\n")
	for i, tab := range tabsFor(v) {
		if i == m.detailTab {
			header.WriteString(titleStyle.Render("["+tab+"]") + "  ")
		} else {
			header.WriteString(tab + "  ")
		}
	}
	header.WriteString("\n" + rule(width) + "\n")
	content := m.detailContent()
	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	available := max(1, m.height-7)
	start := min(max(0, m.detailScroll), max(0, len(lines)-available))
	end := min(len(lines), start+available)
	footer := "\n" + rule(width) + "\nTab/←→ tabs  ↑↓ scroll  r replay  c copy curl  Esc back  q quit"
	if m.currentTab() == "Messages" && !m.eventDetail {
		footer = "\n" + rule(width) + "\n↑↓ select message  Enter details  r replay  c copy curl  Esc back  q quit"
	}
	if m.notice != "" {
		footer += "\n" + clip(safe(m.notice), width)
	}
	return header.String() + strings.Join(lines[start:end], "\n") + footer
}

func (m model) detailContent() string {
	v := m.item
	if v.Proto == "TLS" {
		return fmt.Sprintf("TLS handshake failure\n\n  Server name:  %s\n  Client:       %s\n  Error:        %s\n  Occurrences:  %d\n  First seen:   %s\n\nNo HTTP request was received because TLS failed before it began.",
			safe(resourceName(v.URL)), safe(v.ClientAddr), safe(v.Error), v.ErrorCount, v.Time.Format(time.RFC3339Nano))
	}
	switch m.currentTab() {
	case "Headers":
		var b strings.Builder
		b.WriteString("General\n")
		b.WriteString("  Request URL:     " + safe(v.URL) + "\n")
		b.WriteString("  Request Method:  " + safe(v.Method) + "\n")
		b.WriteString("  Status Code:     " + statusLabel(*v) + " " + http.StatusText(v.Status) + "\n")
		b.WriteString("  HTTP Version:    " + safe(v.Proto) + "\n")
		if v.Error != "" {
			b.WriteString("  Error:           " + safe(v.Error) + "\n")
		}
		b.WriteString("\nResponse Headers\n" + renderHeaders(v.ResponseHeaders))
		b.WriteString("\nRequest Headers\n" + renderHeaders(v.RequestHeaders))
		return b.String()
	case "Payload":
		return payloadView(v)
	case "Preview":
		return "Formatted response\n\n" + formatted(v.ResponseBody, v.ResponseHeaders.Get("Content-Type"), v.ResponseTruncated)
	case "Response":
		return "Response source\n\n" + sourceBody(v.ResponseBody, v.ResponseHeaders.Get("Content-Type"), v.ResponseTruncated)
	case "Cookies":
		return cookiesView(v)
	case "Timing":
		return timingView(v)
	case "Messages":
		return m.messagesView(v)
	case "Scripts":
		return scriptsView(v)
	}
	return ""
}

func (m model) currentTab() string {
	tabs := tabsFor(m.item)
	if m.detailTab >= 0 && m.detailTab < len(tabs) {
		return tabs[m.detailTab]
	}
	return ""
}

func scriptsView(v *store.Session) string {
	var b strings.Builder
	for i, run := range v.ScriptRuns {
		fmt.Fprintf(&b, "%d. %s  [%s]  %s\n", i+1, safe(run.Name), run.Phase, durationLabel(run.Duration))
		if run.Error != "" {
			b.WriteString("  Error: " + safe(run.Error) + "\n")
		}
		if run.Console != "" {
			b.WriteString("  Console:\n" + safe(run.Console) + "\n")
		}
		if run.Display != "" {
			b.WriteString("  Output:\n" + formatted([]byte(run.Display), "", false) + "\n")
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func (m model) messagesView(v *store.Session) string {
	if m.eventDetail && m.eventIndex < len(v.Messages) {
		msg := v.Messages[m.eventIndex]
		var b strings.Builder
		b.WriteString(fmt.Sprintf("Message %d of %d\n", m.eventIndex+1, len(v.Messages)))
		b.WriteString("  Time:       " + msg.Time.Format(time.RFC3339Nano) + "\n")
		b.WriteString("  Protocol:   " + strings.ToUpper(msg.Protocol) + "\n")
		if msg.Protocol == "sse" {
			b.WriteString("  Event:      " + safe(msg.Name) + "\n")
			b.WriteString("  Event ID:   " + safe(msg.EventID) + "\n")
		} else {
			b.WriteString("  Direction:  " + map[bool]string{true: "client → server", false: "server → client"}[msg.FromClient] + "\n")
			b.WriteString(fmt.Sprintf("  Opcode:     %d\n", msg.Type))
		}
		b.WriteString(fmt.Sprintf("  Length:     %s\n\n", humanBytes(int64(len(msg.Body)))))
		b.WriteString(formatted(msg.Body, "", msg.Truncated))
		return b.String()
	}
	if len(v.Messages) == 0 {
		return "No SSE or WebSocket messages yet."
	}
	var b strings.Builder
	b.WriteString("Messages  •  " + fmt.Sprint(len(v.Messages)) + " captured\n")
	b.WriteString("  Name / direction                   Data                         Length       Time\n")
	b.WriteString(rule(max(64, m.width)) + "\n")
	visible := max(1, m.height-11)
	start := max(0, m.eventIndex-visible+1)
	end := min(len(v.Messages), start+visible)
	for i := start; i < end; i++ {
		msg := v.Messages[i]
		label := eventLabel(msg)
		line := fmt.Sprintf("  %-35s %-28s %8s %12s", clip(label, 35), clip(strings.ReplaceAll(preview(msg.Body, msg.Truncated), "\n", " "), 28), humanBytes(int64(len(msg.Body))), msg.Time.Format("15:04:05.000"))
		if i == m.eventIndex {
			line = selectedStyle.Render("›" + line[1:])
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func payloadView(v *store.Session) string {
	var b strings.Builder
	u, err := url.Parse(v.URL)
	if err == nil && len(u.Query()) > 0 {
		b.WriteString("Query String Parameters\n")
		keys := make([]string, 0, len(u.Query()))
		for key := range u.Query() {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			for _, value := range u.Query()[key] {
				b.WriteString("  " + safe(key) + ": " + safe(value) + "\n")
			}
		}
		b.WriteString("\n")
	}
	if strings.HasPrefix(strings.ToLower(v.RequestHeaders.Get("Content-Type")), "application/x-www-form-urlencoded") {
		if form, err := url.ParseQuery(string(v.RequestBody)); err == nil && len(form) > 0 {
			b.WriteString("Form Data\n")
			keys := make([]string, 0, len(form))
			for key := range form {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				for _, value := range form[key] {
					b.WriteString("  " + safe(key) + ": " + safe(value) + "\n")
				}
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("Request Payload\n\n" + formatted(v.RequestBody, v.RequestHeaders.Get("Content-Type"), v.RequestTruncated))
	return b.String()
}

func cookiesView(v *store.Session) string {
	var b strings.Builder
	b.WriteString("Request Cookies\n")
	request := &http.Request{Header: v.RequestHeaders}
	if cookies := request.Cookies(); len(cookies) > 0 {
		for _, cookie := range cookies {
			b.WriteString("  " + safe(cookie.Name) + ": " + safe(cookie.Value) + "\n")
		}
	} else {
		b.WriteString("  (none)\n")
	}
	b.WriteString("\nResponse Cookies\n")
	response := &http.Response{Header: v.ResponseHeaders}
	if cookies := response.Cookies(); len(cookies) > 0 {
		for _, cookie := range cookies {
			b.WriteString("  " + safe(cookie.Name) + ": " + safe(cookie.Value) + "\n")
		}
	} else {
		b.WriteString("  (none)\n")
	}
	return b.String()
}

func timingView(v *store.Session) string {
	if v.Duration == 0 {
		return "Timing\n\n  Request is still in progress or timing was not recorded."
	}
	return fmt.Sprintf("Timing\n\n  Started:   %s\n  Total:     %s\n\n  %s\n\n  Phase breakdown is unavailable; only total duration is recorded.", v.Time.Format(time.RFC3339Nano), durationLabel(v.Duration), strings.Repeat("━", 28))
}

func renderHeaders(h http.Header) string {
	if len(h) == 0 {
		return "  (none)\n"
	}
	keys := make([]string, 0, len(h))
	for key := range h {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		for _, value := range h[key] {
			b.WriteString("  " + safe(key) + ": " + safe(value) + "\n")
		}
	}
	return b.String()
}

func resourceName(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	name := path.Base(u.Path)
	if name == "." || name == "/" || name == "" {
		name = u.Host
	}
	if u.RawQuery != "" {
		name += "?" + u.RawQuery
	}
	return name
}

func resourceType(v store.Session) string {
	if v.Proto == "TLS" {
		return "tls"
	}
	if v.Status == http.StatusSwitchingProtocols {
		return "websocket"
	}
	contentType := v.ResponseHeaders.Get("Content-Type")
	if contentType == "" {
		return "other"
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return contentType
	}
	if mediaType == "text/event-stream" {
		return "eventstream"
	}
	return mediaType
}

func statusLabel(v store.Session) string {
	if v.Error != "" && v.Status == 0 {
		return "failed"
	}
	if v.Status == 0 {
		return "pending"
	}
	return fmt.Sprint(v.Status)
}

func statusBadge(v *store.Session) string {
	label := statusLabel(*v)
	if v.Status >= 400 || v.Error != "" {
		return badStyle.Render(label)
	}
	return goodStyle.Render(label)
}

func durationLabel(d time.Duration) string {
	if d <= 0 {
		return "—"
	}
	if d < time.Second {
		return fmt.Sprintf("%.1f ms", float64(d)/float64(time.Millisecond))
	}
	return fmt.Sprintf("%.2f s", d.Seconds())
}

func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
}

func waterfall(d, maximum time.Duration) string {
	if d <= 0 || maximum <= 0 {
		return "·"
	}
	length := max(1, min(12, int(float64(d)/float64(maximum)*12)))
	return strings.Repeat("━", length)
}

func rule(width int) string {
	return mutedStyle.Render(strings.Repeat("─", min(width, 160)))
}
