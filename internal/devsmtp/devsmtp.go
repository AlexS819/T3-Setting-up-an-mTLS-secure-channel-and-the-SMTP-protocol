// Package devsmtp — мінімальний SMTP-сервер для локальної розробки та
// автотестів. Він не вміє нічого зайвого: приймає лист, зберігає його
// у .eml-файл і показує в лозі. Це дозволяє перевірити весь ланцюжок
// mTLS -> MIME -> SMTP навіть без Mailpit, Docker чи інтернету.
package devsmtp

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Message — прийнятий лист.
type Message struct {
	From       string
	To         []string
	Data       []byte
	ReceivedAt time.Time
	File       string // шлях до .eml, якщо збереження увімкнене
}

// Server — запущений SMTP-сервер.
type Server struct {
	ln     net.Listener
	dir    string
	logger *log.Logger

	mu     sync.Mutex
	msgs   []Message
}

// Start відкриває слухач на addr (можна "127.0.0.1:0") і починає
// обслуговувати клієнтів у фоні. Якщо dir != "", кожен лист пишеться
// у файл. logger може бути nil.
func Start(addr, dir string, logger *log.Logger) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("devsmtp: слухач %s: %w", addr, err)
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("devsmtp: створення каталогу %s: %w", dir, err)
		}
	}
	if logger == nil {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	s := &Server{ln: ln, dir: dir, logger: logger}
	go s.acceptLoop()
	return s, nil
}

// Addr повертає фактичну адресу слухача.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Messages повертає копію списку прийнятих листів.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Message, len(s.msgs))
	copy(out, s.msgs)
	return out
}

// Close зупиняє сервер.
func (s *Server) Close() error {
	return s.ln.Close()
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	reader := bufio.NewReader(conn)

	if !writeLine(conn, "220 devsmtp ESMTP ready") {
		return
	}

	var from string
	var recipients []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		command := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(command, "EHLO"):
			reply(conn, "250-devsmtp\r\n250-8BITMIME\r\n250 SIZE 10485760")
		case strings.HasPrefix(command, "HELO"):
			reply(conn, "250 devsmtp")
		case strings.HasPrefix(command, "MAIL FROM:"):
			from = cleanAddress(line[len("MAIL FROM:"):])
			recipients = nil
			reply(conn, "250 2.1.0 Ok")
		case strings.HasPrefix(command, "RCPT TO:"):
			recipients = append(recipients, cleanAddress(line[len("RCPT TO:"):]))
			reply(conn, "250 2.1.5 Ok")
		case command == "DATA":
			if from == "" {
				reply(conn, "503 5.5.1 Error: need MAIL command")
				continue
			}
			if !writeLine(conn, "354 End data with <CR><LF>.<CR><LF>") {
				return
			}
			data, err := readData(reader)
			if err != nil {
				reply(conn, "451 4.3.0 Error: failed to read message")
				return
			}
			s.store(from, recipients, data)
			reply(conn, "250 2.0.0 Ok: queued")
		case command == "RSET":
			from, recipients = "", nil
			reply(conn, "250 2.0.0 Ok")
		case command == "NOOP":
			reply(conn, "250 2.0.0 Ok")
		case command == "QUIT":
			reply(conn, "221 2.0.0 Bye")
			return
		default:
			reply(conn, "502 5.5.1 Command not implemented")
		}
	}
}

// readData читає тіло листа до рядка з однією крапкою.
func readData(reader *bufio.Reader) ([]byte, error) {
	var sb strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "." {
			return []byte(sb.String()), nil
		}
		// Dot-stuffing (RFC 5321, п. 4.5.2): рядок, що починається з крапки,
		// відправник подвоює її, отримувач — прибирає зайву.
		if strings.HasPrefix(trimmed, "..") {
			trimmed = trimmed[1:]
		}
		sb.WriteString(trimmed)
		sb.WriteString("\r\n")
	}
}

func (s *Server) store(from string, to []string, data []byte) {
	now := time.Now()
	msg := Message{From: from, To: append([]string(nil), to...), Data: data, ReceivedAt: now}

	if s.dir != "" {
		name := fmt.Sprintf("%s.eml", now.Format("20060102-150405.000"))
		path := filepath.Join(s.dir, name)
		if err := os.WriteFile(path, data, 0o644); err == nil {
			msg.File = path
		} else {
			s.logger.Printf("[DEVSMTP] не вдалося зберегти %s: %v", path, err)
		}
	}

	s.mu.Lock()
	s.msgs = append(s.msgs, msg)
	s.mu.Unlock()

	s.logger.Printf("[DEVSMTP] Прийнято лист від <%s> до %v (%d байт)", from, to, len(data))
	if msg.File != "" {
		s.logger.Printf("[DEVSMTP] Збережено: %s", msg.File)
	}
}

func reply(conn net.Conn, text string) {
	_ = writeLine(conn, text)
}

func writeLine(conn net.Conn, text string) bool {
	_, err := fmt.Fprintf(conn, "%s\r\n", text)
	return err == nil
}

// cleanAddress прибирає кутові дужки та параметри після адреси.
func cleanAddress(value string) string {
	value = strings.TrimSpace(value)
	if start := strings.IndexByte(value, '<'); start >= 0 {
		if end := strings.IndexByte(value[start:], '>'); end > 0 {
			return value[start+1 : start+end]
		}
	}
	if space := strings.IndexAny(value, " \t"); space >= 0 {
		return value[:space]
	}
	return value
}
