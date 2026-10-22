package store

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Filter is a parsed expression shared by the TUI, exports, and live output.
type Filter struct{ root filterNode }

type filterNode interface {
	sql() (string, []any)
	match(*Session) bool
}

type termNode struct{ field, value string }
type binaryNode struct {
	op          string
	left, right filterNode
}
type notNode struct{ child filterNode }

func ParseFilter(input string) (*Filter, error) {
	tokens, err := filterTokens(input)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return &Filter{}, nil
	}
	p := filterParser{tokens: tokens}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(tokens) {
		return nil, fmt.Errorf("unexpected filter token %q", tokens[p.pos])
	}
	return &Filter{root: root}, nil
}

func (f *Filter) Match(v *Session) bool { return f == nil || f.root == nil || f.root.match(v) }

func (f *Filter) SQL() (string, []any) {
	if f == nil || f.root == nil {
		return "", nil
	}
	return f.root.sql()
}

func (f *Filter) WithKind(kind string) *Filter {
	if kind == "" {
		return f
	}
	result := &Filter{root: termNode{field: "kind", value: kind}}
	if f != nil && f.root != nil {
		result.root = binaryNode{op: "AND", left: f.root, right: result.root}
	}
	return result
}

func filterTokens(input string) ([]string, error) {
	var tokens []string
	for i := 0; i < len(input); {
		if input[i] == ' ' || input[i] == '\t' || input[i] == '\n' {
			i++
			continue
		}
		if strings.ContainsRune("()&|!", rune(input[i])) {
			tokens = append(tokens, input[i:i+1])
			i++
			continue
		}
		var word strings.Builder
		var quote byte
		for i < len(input) {
			c := input[i]
			if quote != 0 {
				if c == quote {
					quote = 0
					i++
					continue
				}
				if c == '\\' && i+1 < len(input) && (input[i+1] == quote || input[i+1] == '\\') {
					i++
					c = input[i]
				}
				word.WriteByte(c)
				i++
				continue
			}
			if c == '\'' || c == '"' {
				quote = c
				i++
				continue
			}
			if c == ' ' || c == '\t' || c == '\n' || strings.ContainsRune("()&|!", rune(c)) {
				break
			}
			word.WriteByte(c)
			i++
		}
		if quote != 0 {
			return nil, fmt.Errorf("unterminated filter quote")
		}
		if word.Len() > 0 {
			tokens = append(tokens, word.String())
		}
	}
	return tokens, nil
}

type filterParser struct {
	tokens []string
	pos    int
}

func (p *filterParser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *filterParser) parseOr() (filterNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek() == "|" || strings.EqualFold(p.peek(), "or") {
		p.pos++
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = binaryNode{op: "OR", left: left, right: right}
	}
	return left, nil
}

func (p *filterParser) parseAnd() (filterNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peek() != "" && p.peek() != ")" && p.peek() != "|" && !strings.EqualFold(p.peek(), "or") {
		if p.peek() == "&" || strings.EqualFold(p.peek(), "and") {
			p.pos++
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = binaryNode{op: "AND", left: left, right: right}
	}
	return left, nil
}

func (p *filterParser) parseUnary() (filterNode, error) {
	switch {
	case p.peek() == "!" || strings.EqualFold(p.peek(), "not"):
		p.pos++
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{child: child}, nil
	case p.peek() == "(":
		p.pos++
		child, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("missing closing filter parenthesis")
		}
		p.pos++
		return child, nil
	case p.peek() == "" || p.peek() == ")" || p.peek() == "&" || p.peek() == "|":
		return nil, fmt.Errorf("missing filter term")
	default:
		word := p.peek()
		p.pos++
		field, value, found := strings.Cut(word, ":")
		if !found || value == "" {
			return termNode{field: "text", value: word}, nil
		}
		field = strings.ToLower(field)
		switch field {
		case "url", "method", "status", "client", "ip", "proto", "protocol", "kind", "req", "request", "resp", "response", "error":
			return termNode{field: field, value: value}, nil
		default:
			return termNode{field: "text", value: word}, nil
		}
	}
}

func (n binaryNode) sql() (string, []any) {
	left, la := n.left.sql()
	right, ra := n.right.sql()
	return "(" + left + " " + n.op + " " + right + ")", append(la, ra...)
}
func (n binaryNode) match(v *Session) bool {
	if n.op == "OR" {
		return n.left.match(v) || n.right.match(v)
	}
	return n.left.match(v) && n.right.match(v)
}
func (n notNode) sql() (string, []any) {
	inner, args := n.child.sql()
	return "NOT (" + inner + ")", args
}
func (n notNode) match(v *Session) bool { return !n.child.match(v) }

func (n termNode) sql() (string, []any) {
	value := n.value
	switch n.field {
	case "url":
		return "instr(lower(url),lower(?))>0", []any{value}
	case "method":
		return "lower(method)=lower(?)", []any{value}
	case "status":
		if strings.HasSuffix(strings.ToLower(value), "xx") && len(value) == 3 && value[0] >= '1' && value[0] <= '5' {
			start := int(value[0]-'0') * 100
			return "(status>=? AND status<?)", []any{start, start + 100}
		}
		return "status=?", []any{value}
	case "client", "ip":
		return "instr(lower(client_addr),lower(?))>0", []any{value}
	case "kind":
		return "kind=?", []any{strings.ToLower(value)}
	case "error":
		return "instr(lower(COALESCE(error,'')),lower(?))>0", []any{value}
	case "req", "request":
		return "(instr(lower(url),lower(?))>0 OR " + bodySearchSQL("req") + ")", append([]any{value}, bodySearchArgs(value)...)
	case "resp", "response":
		return "(instr(CAST(status AS TEXT),?)>0 OR " + bodySearchSQL("resp") + ")", append([]any{value}, bodySearchArgs(value)...)
	case "proto", "protocol":
		switch strings.ToLower(value) {
		case "http", "https", "ws", "wss":
			return "lower(url) LIKE ?", []any{strings.ToLower(value) + "://%"}
		case "websocket":
			return "status=101", nil
		case "sse":
			return "instr(lower(resp_headers),'text/event-stream')>0", nil
		case "h2", "http2":
			return "proto='HTTP/2.0'", nil
		case "http1":
			return "proto='HTTP/1.1'", nil
		default:
			return "instr(lower(proto),lower(?))>0", []any{value}
		}
	default:
		return "(instr(lower(url),lower(?))>0 OR instr(lower(method),lower(?))>0 OR instr(CAST(status AS TEXT),?)>0 OR instr(lower(COALESCE(error,'')),lower(?))>0 OR " + bodySearchSQL("req") + " OR " + bodySearchSQL("resp") + ")", append([]any{value, value, value, value}, append(bodySearchArgs(value), bodySearchArgs(value)...)...)
	}
}

func (n termNode) match(v *Session) bool {
	if v == nil {
		return false
	}
	contains := func(text string) bool { return strings.Contains(strings.ToLower(text), strings.ToLower(n.value)) }
	request := func() bool {
		return contains(v.URL) || headerOrBodyContains(v.RequestHeaders, v.RequestBody, n.value) || contains(string(scriptDisplay(v.ScriptRuns, "request")))
	}
	response := func() bool {
		return contains(strconv.Itoa(v.Status)) || headerOrBodyContains(v.ResponseHeaders, v.ResponseBody, n.value) || contains(string(scriptDisplay(v.ScriptRuns, "response")))
	}
	switch n.field {
	case "url":
		return contains(v.URL)
	case "method":
		return strings.EqualFold(v.Method, n.value)
	case "status":
		if strings.HasSuffix(strings.ToLower(n.value), "xx") && len(n.value) == 3 && n.value[0] >= '1' && n.value[0] <= '5' {
			return strconv.Itoa(v.Status/100) == n.value[:1]
		}
		return strconv.Itoa(v.Status) == n.value
	case "client", "ip":
		return contains(v.ClientAddr)
	case "kind":
		kind := v.Kind
		if kind == "" {
			kind = ResourceKind(*v)
		}
		return strings.EqualFold(kind, n.value)
	case "error":
		return contains(v.Error)
	case "req", "request":
		return request()
	case "resp", "response":
		return response()
	case "proto", "protocol":
		switch strings.ToLower(n.value) {
		case "http", "https", "ws", "wss":
			return strings.HasPrefix(strings.ToLower(v.URL), strings.ToLower(n.value)+"://")
		case "websocket":
			return v.Status == http.StatusSwitchingProtocols
		case "sse":
			return strings.Contains(strings.ToLower(v.ResponseHeaders.Get("Content-Type")), "text/event-stream")
		case "h2", "http2":
			return v.Proto == "HTTP/2.0"
		case "http1":
			return v.Proto == "HTTP/1.1"
		default:
			return contains(v.Proto)
		}
	default:
		return contains(v.URL) || contains(v.Method) || contains(strconv.Itoa(v.Status)) || contains(v.Error) || request() || response()
	}
}

func headerOrBodyContains(headers http.Header, body []byte, value string) bool {
	needle := strings.ToLower(value)
	for name, values := range headers {
		if strings.Contains(strings.ToLower(name), needle) {
			return true
		}
		for _, text := range values {
			if strings.Contains(strings.ToLower(text), needle) {
				return true
			}
		}
	}
	if strings.Contains(strings.ToLower(string(body)), needle) {
		return true
	}
	return strings.Contains(strings.ToLower(string(decodedSearchBody(body, headers))), needle)
}
