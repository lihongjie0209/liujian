package tui

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/aymanbagabas/go-osc52/v2"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/lihongjie0209/liujian/internal/firewall"
	"github.com/lihongjie0209/liujian/internal/replay"
	"github.com/lihongjie0209/liujian/internal/store"
	"github.com/yosssi/gohtml"
)

type model struct {
	store         *store.Store
	rows          []store.Session
	selected      int
	selectedKind  int
	filter        string
	editing       bool
	detail        bool
	detailTab     int
	detailScroll  int
	eventIndex    int
	eventDetail   bool
	item          *store.Session
	ctx           context.Context
	notice        string
	replaying     bool
	width, height int
	errorText     string
	live          bool
	listeners     Listeners
	firewall      *firewall.Status
}

// Listeners describes the active capture endpoints shown in the live TUI.
type Listeners struct {
	IP              string
	PhoneIPs        []string
	AllowHosts      []string
	AllowClients    []string
	DNSAnswerRules  []string
	TLSFailureCount func() uint64
	CACompromised   bool
	DNSPort         int
	HTTPPorts       []int
	HTTPSPorts      []int
	ProxyPort       int
}

func Run(ctx context.Context, s *store.Store, listeners *Listeners) error {
	m := model{store: s, ctx: ctx, live: listeners != nil, width: 100, height: 30}
	if listeners != nil {
		m.listeners = *listeners
	}
	_, err := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx)).Run()
	if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, tea.ErrProgramKilled)) {
		return nil
	}
	return err
}

func (m model) Init() tea.Cmd {
	if m.live {
		return tea.Batch(tick(), checkFirewall(), firewallTick())
	}
	return tick()
}

type tickMsg struct{}

var kindFilters = []struct{ label, kind string }{
	{"All", ""}, {"Fetch/XHR", "fetch"}, {"Doc", "doc"}, {"CSS", "css"}, {"JS", "js"},
	{"Img", "img"}, {"Media", "media"}, {"Font", "font"}, {"WS", "ws"}, {"SSE", "sse"},
	{"Manifest", "manifest"}, {"Wasm", "wasm"}, {"TLS", "tls"}, {"Other", "other"},
}

func (m *model) refreshRows() {
	filter, err := store.ParseFilter(m.filter)
	if err != nil {
		m.errorText = err.Error()
		return
	}
	rows, err := m.store.ListFiltered(500, filter.WithKind(kindFilters[m.selectedKind].kind))
	if err != nil {
		m.errorText = err.Error()
		return
	}
	m.errorText = ""
	m.rows = rows
	if m.selected >= len(rows) {
		m.selected = len(rows) - 1
	}
	if m.selected < 0 {
		m.selected = 0
	}
}

type firewallTickMsg struct{}
type firewallResultMsg struct{ status firewall.Status }
type replayResultMsg struct {
	id     int64
	status int
	err    error
}
type copyResultMsg struct{ err error }

func tick() tea.Cmd { return tea.Tick(time.Second, func(time.Time) tea.Msg { return tickMsg{} }) }

func firewallTick() tea.Cmd {
	return tea.Tick(15*time.Second, func(time.Time) tea.Msg { return firewallTickMsg{} })
}

func checkFirewall() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return firewallResultMsg{status: firewall.Check(ctx)}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = v.Width
		m.height = v.Height
	case tickMsg:
		m.refreshRows()
		if m.errorText == "" {
			if m.detail && m.item != nil {
				if item, err := m.store.Get(m.item.ID); err == nil {
					m.item = item
				}
			}
		}
		return m, tick()
	case firewallTickMsg:
		return m, tea.Batch(checkFirewall(), firewallTick())
	case firewallResultMsg:
		m.firewall = &v.status
	case replayResultMsg:
		m.replaying = false
		if v.err != nil {
			m.notice = "Replay failed: " + v.err.Error()
		} else {
			m.notice = fmt.Sprintf("Replayed as session %d (HTTP %d)", v.id, v.status)
			m.refreshRows()
		}
	case copyResultMsg:
		if v.err != nil {
			m.notice = "Copy curl failed: " + v.err.Error()
		} else {
			m.notice = "Sent curl command to terminal clipboard (OSC52)"
		}
	case tea.KeyMsg:
		if m.editing {
			switch v.String() {
			case "enter":
				m.editing = false
				m.selected = 0
				m.refreshRows()
			case "esc":
				m.editing = false
			case "backspace":
				if len(m.filter) > 0 {
					m.filter = m.filter[:len(m.filter)-1]
				}
			default:
				if len(v.Runes) > 0 {
					m.filter += string(v.Runes)
				}
			}
			return m, nil
		}
		switch v.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			if m.detail && !m.eventDetail {
				m.detailTab = (m.detailTab + 1) % tabCount(m.item)
				m.detailScroll = 0
			}
		case "right":
			if m.detail && !m.eventDetail {
				m.detailTab = (m.detailTab + 1) % tabCount(m.item)
				m.detailScroll = 0
			} else if !m.detail {
				m.selectedKind = (m.selectedKind + 1) % len(kindFilters)
				m.selected = 0
				m.refreshRows()
			}
		case "shift+tab":
			if m.detail && !m.eventDetail {
				m.detailTab = (m.detailTab + tabCount(m.item) - 1) % tabCount(m.item)
				m.detailScroll = 0
			}
		case "left":
			if m.detail && !m.eventDetail {
				m.detailTab = (m.detailTab + tabCount(m.item) - 1) % tabCount(m.item)
				m.detailScroll = 0
			} else if !m.detail {
				m.selectedKind = (m.selectedKind + len(kindFilters) - 1) % len(kindFilters)
				m.selected = 0
				m.refreshRows()
			}
		case "0":
			if !m.detail {
				m.selectedKind = 0
				m.selected = 0
				m.refreshRows()
			}
		case "/":
			if !m.detail {
				m.editing = true
			}
		case "esc":
			if m.eventDetail {
				m.eventDetail = false
			} else {
				m.detail = false
			}
		case "r":
			if m.detail && m.item != nil && !m.replaying {
				id := m.item.ID
				db := m.store
				ctx := m.ctx
				if ctx == nil {
					ctx = context.Background()
				}
				m.replaying = true
				m.notice = "Replaying request..."
				return m, func() tea.Msg {
					result, err := replay.Send(ctx, db, id, 30*time.Second)
					if err != nil {
						return replayResultMsg{err: err}
					}
					return replayResultMsg{id: result.ID, status: result.Status}
				}
			}
		case "c":
			if m.detail && m.item != nil {
				line, err := replay.Curl(m.item)
				if err != nil {
					m.notice = "Copy curl failed: " + err.Error()
					return m, nil
				}
				return m, func() tea.Msg {
					_, err := fmt.Fprint(os.Stderr, osc52.New(line))
					return copyResultMsg{err: err}
				}
			}
		case "up", "k":
			if m.detail && m.currentTab() == "Messages" && !m.eventDetail {
				if m.eventIndex > 0 {
					m.eventIndex--
				}
			} else if m.detail && m.detailScroll > 0 {
				m.detailScroll--
			} else if !m.detail && m.selected > 0 {
				m.selected--
			}
		case "down", "j":
			if m.detail && m.currentTab() == "Messages" && !m.eventDetail {
				if m.item != nil && m.eventIndex+1 < len(m.item.Messages) {
					m.eventIndex++
				}
			} else if m.detail {
				m.detailScroll++
			} else if m.selected+1 < len(m.rows) {
				m.selected++
			}
		case "pgup":
			if m.detail && m.currentTab() == "Messages" && !m.eventDetail {
				m.eventIndex = max(0, m.eventIndex-max(1, m.height-12))
			} else if m.detail {
				m.detailScroll -= m.height - 2
				if m.detailScroll < 0 {
					m.detailScroll = 0
				}
			}
		case "pgdown":
			if m.detail && m.currentTab() == "Messages" && !m.eventDetail && m.item != nil {
				m.eventIndex = min(len(m.item.Messages)-1, m.eventIndex+max(1, m.height-12))
				m.eventIndex = max(0, m.eventIndex)
			} else if m.detail {
				m.detailScroll += m.height - 2
			}
		case "enter":
			if m.detail && m.currentTab() == "Messages" && !m.eventDetail && m.item != nil && len(m.item.Messages) > 0 {
				m.eventDetail = true
				m.detailScroll = 0
			} else if !m.detail && len(m.rows) > 0 {
				item, err := m.store.Get(m.rows[m.selected].ID)
				if err != nil {
					m.errorText = err.Error()
				} else {
					m.item = item
					m.detail = true
					m.detailTab = 0
					m.eventIndex = 0
					m.detailScroll = 0
				}
			}
		}
	}
	return m, nil
}

func eventLabel(msg store.Message) string {
	if msg.Protocol == "sse" {
		name := msg.Name
		if name == "" {
			name = "message"
		}
		if msg.EventID != "" {
			return fmt.Sprintf("%s SSE %s id=%s", msg.Time.Format("15:04:05.000"), safe(name), safe(msg.EventID))
		}
		return fmt.Sprintf("%s SSE %s", msg.Time.Format("15:04:05.000"), safe(name))
	}
	direction := "←"
	if msg.FromClient {
		direction = "→"
	}
	kind := "binary"
	if msg.Type == 1 {
		kind = "text"
	}
	return fmt.Sprintf("%s WS %s %s", msg.Time.Format("15:04:05.000"), direction, kind)
}

func formatted(body []byte, mime string, truncated bool) string {
	return bodyView(body, mime, truncated, true)
}

func sourceBody(body []byte, mime string, truncated bool) string {
	return bodyView(body, mime, truncated, false)
}

func bodyView(body []byte, mime string, truncated, pretty bool) string {
	if len(body) == 0 {
		return "(empty)"
	}
	if !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return preview(body, truncated)
	}
	const displayLimit = 64 << 10
	limited := body
	if len(limited) > displayLimit {
		limited = limited[:displayLimit]
		truncated = true
	}
	content := safe(string(limited))
	lexer := ""
	lowerMime := strings.ToLower(mime)
	if strings.Contains(lowerMime, "json") || json.Valid(limited) {
		lexer = "json"
		if pretty {
			var indented bytes.Buffer
			if json.Indent(&indented, limited, "", "  ") == nil {
				content = indented.String()
			}
		}
	} else if strings.Contains(lowerMime, "html") {
		lexer = "html"
		if pretty {
			content = gohtml.Format(content)
		}
	} else if strings.Contains(lowerMime, "xml") {
		lexer = "xml"
	} else if strings.Contains(lowerMime, "javascript") {
		lexer = "javascript"
	} else if strings.Contains(lowerMime, "css") {
		lexer = "css"
	}
	if lexer != "" {
		var highlighted bytes.Buffer
		if quick.Highlight(&highlighted, content, lexer, "terminal256", "github-dark") == nil {
			content = highlighted.String()
		}
	}
	if truncated {
		content += "\n[truncated]"
	}
	return content
}

func preview(body []byte, truncated bool) string {
	var s string
	if !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		n := len(body)
		if n > 64 {
			n = 64
		}
		s = fmt.Sprintf("[binary %d bytes] %s", len(body), hex.EncodeToString(body[:n]))
	} else {
		s = safe(string(body))
		r := []rune(s)
		if len(r) > 4096 {
			s = string(r[:4096]) + "…"
		}
	}
	if truncated {
		s += " [truncated]"
	}
	return s
}
func safe(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 32 || r == 127 {
			return '�'
		}
		return r
	}, s)
}
func clip(s string, n int) string {
	if n < 1 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
