package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Logger prints to stdout (for `docker logs`) and keeps the last lines for the UI.
type Logger struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func NewLogger(max int) *Logger { return &Logger{max: max} }

func (l *Logger) Printf(src, format string, a ...any) {
	line := fmt.Sprintf("%s [%s] %s", time.Now().Format("2006-01-02 15:04:05"), src, fmt.Sprintf(format, a...))
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Println(line)
	l.lines = append(l.lines, line)
	if len(l.lines) > l.max {
		l.lines = append([]string(nil), l.lines[len(l.lines)-l.max:]...)
	}
}

func (l *Logger) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// Writer returns an io.Writer that logs each line written to it, for child process output.
func (l *Logger) Writer(src string) io.Writer { return &lineWriter{l: l, src: src} }

type lineWriter struct {
	l   *Logger
	src string
	buf []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(w.buf[:i]), "\r")
		w.buf = w.buf[i+1:]
		if strings.TrimSpace(line) != "" {
			w.l.Printf(w.src, "%s", line)
		}
	}
	return len(p), nil
}
