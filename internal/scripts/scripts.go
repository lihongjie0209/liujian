package scripts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lihongjie0209/liujian/internal/store"
	"github.com/dop251/goja"
)

type Config struct {
	Scripts []Definition `json:"scripts"`
}

type Definition struct {
	Name      string   `json:"name"`
	File      string   `json:"file"`
	Phases    []string `json:"phases,omitempty"`
	TimeoutMS int      `json:"timeout_ms,omitempty"`
}

type compiled struct {
	definition Definition
	program    *goja.Program
}

type Runner struct{ scripts []compiled }

var errPhaseNotImplemented = errors.New("script does not implement this phase")

type Exchange struct {
	Method  string
	URL     string
	Status  int
	Headers http.Header
	Body    []byte
}

func Load(path string) (*Runner, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read script config: %w", err)
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode script config: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("script config must contain one JSON object")
	}
	if len(cfg.Scripts) == 0 {
		return nil, errors.New("script config has no scripts")
	}
	runner := &Runner{}
	for i, script := range cfg.Scripts {
		if script.Name == "" || script.File == "" {
			return nil, fmt.Errorf("script %d needs name and file", i+1)
		}
		if script.TimeoutMS == 0 {
			script.TimeoutMS = 2000
		}
		if script.TimeoutMS < 1 || script.TimeoutMS > 60000 {
			return nil, fmt.Errorf("script %s timeout_ms must be 1..60000", script.Name)
		}
		for _, phase := range script.Phases {
			if phase != "request" && phase != "response" {
				return nil, fmt.Errorf("script %s has invalid phase %q", script.Name, phase)
			}
		}
		file := script.File
		if !filepath.IsAbs(file) {
			file = filepath.Join(filepath.Dir(path), file)
		}
		source, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("script %s: %w", script.Name, err)
		}
		program, err := goja.Compile(file, string(source), false)
		if err != nil {
			return nil, fmt.Errorf("script %s: %w", script.Name, err)
		}
		runner.scripts = append(runner.scripts, compiled{definition: script, program: program})
	}
	return runner, nil
}

func (r *Runner) Apply(ctx context.Context, phase string, exchange Exchange, maxBody int64) (Exchange, []store.ScriptRun) {
	if r == nil {
		return exchange, nil
	}
	var runs []store.ScriptRun
	for _, script := range r.scripts {
		if len(script.definition.Phases) > 0 && !contains(script.definition.Phases, phase) {
			continue
		}
		start := time.Now()
		next, display, output, err := run(ctx, script, phase, exchange, maxBody)
		if errors.Is(err, errPhaseNotImplemented) {
			continue
		}
		entry := store.ScriptRun{Name: script.definition.Name, Phase: phase, Display: display, Console: output, Duration: time.Since(start)}
		if err != nil {
			entry.Error = err.Error()
		} else {
			exchange = next
		}
		runs = append(runs, entry)
	}
	return exchange, runs
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func run(ctx context.Context, script compiled, phase string, current Exchange, maxBody int64) (Exchange, string, string, error) {
	vm := goja.New()
	var logs strings.Builder
	if err := installBuiltins(vm, maxBody, &logs); err != nil {
		return current, "", "", err
	}
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			vm.Interrupt(ctx.Err())
		case <-time.After(time.Duration(script.definition.TimeoutMS) * time.Millisecond):
			vm.Interrupt(errors.New("script timeout"))
		case <-finished:
		}
	}()
	if _, err := vm.RunProgram(script.program); err != nil {
		return current, "", logs.String(), err
	}
	functionName := "onRequest"
	if phase == "response" {
		functionName = "onResponse"
	}
	function, ok := goja.AssertFunction(vm.Get(functionName))
	if !ok {
		return current, "", logs.String(), errPhaseNotImplemented
	}
	object := vm.NewObject()
	_ = object.Set("method", current.Method)
	_ = object.Set("url", current.URL)
	_ = object.Set("status", current.Status)
	headersObject := vm.NewObject()
	for name, values := range current.Headers {
		_ = headersObject.Set(name, append([]string(nil), values...))
	}
	_ = object.Set("headers", headersObject)
	_ = vm.Set("__body", vm.NewArrayBuffer(append([]byte(nil), current.Body...)))
	body, err := vm.RunString("new Uint8Array(__body)")
	if err != nil {
		return current, "", logs.String(), err
	}
	_ = object.Set("body", body)
	value, err := function(goja.Undefined(), object)
	if err != nil {
		return current, "", logs.String(), err
	}
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return current, "", logs.String(), errors.New("script must return a request or response object")
	}
	result := value.ToObject(vm)
	display := ""
	if v := result.Get("display"); v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
		display = v.String()
	}
	next := current
	if v := result.Get("method"); v != nil && !goja.IsUndefined(v) {
		if v.String() == "" || phase != "request" && v.String() != current.Method {
			return current, display, logs.String(), errors.New("method can only change during request")
		}
		next.Method = v.String()
	}
	if v := result.Get("url"); v != nil && !goja.IsUndefined(v) {
		oldURL, oldErr := url.Parse(current.URL)
		newURL, newErr := url.Parse(v.String())
		if phase != "request" && v.String() != current.URL || oldErr != nil || newErr != nil || oldURL.Scheme != newURL.Scheme || !strings.EqualFold(oldURL.Host, newURL.Host) {
			return current, display, logs.String(), errors.New("script URL must keep the original scheme and host")
		}
		next.URL = v.String()
	}
	if v := result.Get("status"); v != nil && !goja.IsUndefined(v) {
		status := int(v.ToInteger())
		if phase != "response" && status != current.Status || phase == "response" && (status < 100 || status > 599) {
			return current, display, logs.String(), errors.New("invalid script status")
		}
		next.Status = status
	}
	if v := result.Get("headers"); v != nil && !goja.IsUndefined(v) {
		var headers http.Header
		if err := vm.ExportTo(v, &headers); err != nil {
			return current, display, logs.String(), fmt.Errorf("script headers: %w", err)
		}
		next.Headers = make(http.Header, len(headers))
		for name, values := range headers {
			key := http.CanonicalHeaderKey(name)
			next.Headers[key] = append(next.Headers[key], values...)
		}
	}
	if v := result.Get("body"); v != nil && !goja.IsUndefined(v) {
		var bytes []byte
		if err := vm.ExportTo(v, &bytes); err != nil {
			return current, display, logs.String(), fmt.Errorf("script body must be Uint8Array: %w", err)
		}
		if maxBody > 0 && int64(len(bytes)) > maxBody {
			return current, display, logs.String(), errors.New("script body exceeds capture body limit")
		}
		next.Body = append([]byte(nil), bytes...)
	}
	if len(logs.String()) > 2<<20 || len(display) > 2<<20 {
		return current, "", "", errors.New("script output exceeds 2 MiB")
	}
	return next, display, logs.String(), nil
}
