package headless

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/lihongjie0209/liujian/internal/store"
)

type Output struct {
	Writer      io.Writer
	Format      string
	BodyDir     string
	InlineBytes int
}

type Body struct {
	Size      int    `json:"size"`
	Encoding  string `json:"encoding,omitempty"`
	Text      string `json:"text,omitempty"`
	Base64    string `json:"base64,omitempty"`
	Path      string `json:"path,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type Event struct {
	Type            string            `json:"type"`
	ID              int64             `json:"id"`
	SessionID       int64             `json:"session_id,omitempty"`
	Time            string            `json:"time"`
	DurationMS      float64           `json:"duration_ms,omitempty"`
	Method          string            `json:"method,omitempty"`
	URL             string            `json:"url,omitempty"`
	Protocol        string            `json:"protocol,omitempty"`
	Status          int               `json:"status,omitempty"`
	ClientAddr      string            `json:"client_addr,omitempty"`
	Error           string            `json:"error,omitempty"`
	ErrorCount      int               `json:"error_count,omitempty"`
	RequestHeaders  http.Header       `json:"request_headers,omitempty"`
	ResponseHeaders http.Header       `json:"response_headers,omitempty"`
	RequestBody     *Body             `json:"request_body,omitempty"`
	ResponseBody    *Body             `json:"response_body,omitempty"`
	Direction       string            `json:"direction,omitempty"`
	Name            string            `json:"name,omitempty"`
	EventID         string            `json:"event_id,omitempty"`
	MessageType     int               `json:"message_type,omitempty"`
	Body            *Body             `json:"body,omitempty"`
	Scripts         []store.ScriptRun `json:"scripts,omitempty"`
}

func (o *Output) Validate() error {
	if o.Writer == nil {
		return fmt.Errorf("headless output writer is required")
	}
	if o.Format != "console" && o.Format != "jsonl" {
		return fmt.Errorf("headless format must be console or jsonl")
	}
	if o.InlineBytes < 0 {
		return fmt.Errorf("inline body threshold cannot be negative")
	}
	return nil
}

func (o *Output) WriteSession(v *store.Session) error {
	req, err := o.body(v.RequestBody, v.RequestTruncated, fmt.Sprintf("session-%d-request", v.ID))
	if err != nil {
		return err
	}
	resp, err := o.body(v.ResponseBody, v.ResponseTruncated, fmt.Sprintf("session-%d-response", v.ID))
	if err != nil {
		return err
	}
	e := Event{Type: "session", ID: v.ID, Time: v.Time.Format("2006-01-02T15:04:05.000000000Z07:00"), DurationMS: float64(v.Duration.Microseconds()) / 1000, Method: v.Method, URL: v.URL, Protocol: v.Proto, Status: v.Status, ClientAddr: v.ClientAddr, Error: v.Error, ErrorCount: v.ErrorCount, RequestHeaders: v.RequestHeaders, ResponseHeaders: v.ResponseHeaders, RequestBody: req, ResponseBody: resp, Scripts: v.ScriptRuns}
	return o.write(e)
}

func (o *Output) WriteMessage(v store.StreamMessage) error {
	body, err := o.body(v.Body, v.Truncated, fmt.Sprintf("message-%d", v.ID))
	if err != nil {
		return err
	}
	direction := "server_to_client"
	if v.FromClient {
		direction = "client_to_server"
	}
	e := Event{Type: v.Protocol + "_message", ID: v.ID, SessionID: v.SessionID, Time: v.Time.Format("2006-01-02T15:04:05.000000000Z07:00"), Direction: direction, Name: v.Name, EventID: v.EventID, MessageType: v.Message.Type, Body: body}
	return o.write(e)
}

func (o *Output) body(data []byte, truncated bool, name string) (*Body, error) {
	if len(data) == 0 && !truncated {
		return nil, nil
	}
	b := &Body{Size: len(data), Truncated: truncated}
	if len(data) > o.InlineBytes {
		if err := os.MkdirAll(o.BodyDir, 0o700); err != nil {
			return nil, err
		}
		file, err := os.CreateTemp(o.BodyDir, name+"-*.body")
		if err != nil {
			return nil, err
		}
		path, err := filepath.Abs(file.Name())
		if err != nil {
			file.Close()
			os.Remove(file.Name())
			return nil, err
		}
		if _, err := file.Write(data); err != nil {
			file.Close()
			os.Remove(path)
			return nil, err
		}
		if err := file.Close(); err != nil {
			os.Remove(path)
			return nil, err
		}
		b.Path = path
		return b, nil
	}
	if utf8.Valid(data) && !strings.ContainsRune(string(data), 0) {
		b.Encoding, b.Text = "utf-8", string(data)
	} else {
		b.Encoding, b.Base64 = "base64", base64.StdEncoding.EncodeToString(data)
	}
	return b, nil
}

func (o *Output) write(e Event) error {
	if o.Format == "jsonl" {
		return json.NewEncoder(o.Writer).Encode(e)
	}
	if e.Type == "session" {
		if _, err := fmt.Fprintf(o.Writer, "[%s] #%d %s %s → %d (%g ms)", e.Time, e.ID, e.Method, e.URL, e.Status, e.DurationMS); err != nil {
			return err
		}
		if e.Error != "" {
			if _, err := fmt.Fprintf(o.Writer, " ERROR %s", e.Error); err != nil {
				return err
			}
		}
		for _, headers := range []struct {
			label string
			value http.Header
		}{{"request_headers", e.RequestHeaders}, {"response_headers", e.ResponseHeaders}} {
			if len(headers.value) == 0 {
				continue
			}
			encoded, err := json.Marshal(headers.value)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(o.Writer, "\n  %s: %s", headers.label, encoded); err != nil {
				return err
			}
		}
	} else {
		if _, err := fmt.Fprintf(o.Writer, "[%s] #%d %s session=%d %s", e.Time, e.ID, e.Type, e.SessionID, e.Direction); err != nil {
			return err
		}
	}
	for _, part := range []struct {
		label string
		body  *Body
	}{{"request", e.RequestBody}, {"response", e.ResponseBody}, {"body", e.Body}} {
		if part.body == nil {
			continue
		}
		if part.body.Path != "" {
			if _, err := fmt.Fprintf(o.Writer, "\n  %s: %s (%d bytes)", part.label, part.body.Path, part.body.Size); err != nil {
				return err
			}
		} else if part.body.Encoding == "utf-8" {
			if _, err := fmt.Fprintf(o.Writer, "\n  %s: %q", part.label, part.body.Text); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(o.Writer, "\n  %s: base64:%s", part.label, part.body.Base64); err != nil {
				return err
			}
		}
	}
	for _, run := range e.Scripts {
		if _, err := fmt.Fprintf(o.Writer, "\n  script %s [%s]: output=%q console=%q error=%q", run.Name, run.Phase, run.Display, run.Console, run.Error); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(o.Writer)
	return err
}
