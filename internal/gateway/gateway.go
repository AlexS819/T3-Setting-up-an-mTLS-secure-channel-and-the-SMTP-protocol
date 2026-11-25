// Package gateway реалізує mTLS TCP-сервер шлюзу критичних сповіщень.
// Сервер приймає лише тих клієнтів, чий сертифікат підписаний довіреним CA,
// фіксує ідентичність клієнта і передає подію підписнику (notifier).
package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"secure-alert-gateway/internal/pki"
)

// Відповіді, які шлюз надсилає клієнту.
const (
	ReplyVerified       = "[SERVER]: ALERT RECEIVED AND VERIFIED"
	ReplyDispatched     = "[SERVER]: ALERT PROCESSED AND DISPATCHED"
	ReplyDispatchFailed = "[SERVER]: ALERT RECEIVED, EMAIL DISPATCH FAILED"
)

const maxMessageSize = 64 << 10 // 64 КіБ — захист від нескінченного потоку даних

// Alert — одна подія, зафіксована шлюзом.
type Alert struct {
	Message    string
	ReceivedAt time.Time
	Client     pki.Identity
	RemoteAddr string
	TLSVersion string
}

// Notifier — те, що шлюз робить з прийнятою подією (у нашому випадку —
// формує та надсилає лист). Якщо Notifier == nil, шлюз працює в режимі
// Рівня 1: лише підтверджує прийом.
type Notifier func(ctx context.Context, alert Alert) error

// Config описує налаштування шлюзу.
type Config struct {
	Addr        string        // наприклад, ":8443"
	CertFile    string        // certs/server.crt
	KeyFile     string        // certs/server.key
	CAFile      string        // certs/ca.crt
	ReadTimeout time.Duration // скільки чекати повідомлення від клієнта
	Notifier    Notifier
	Logger      *log.Logger
}

// Server — готовий до запуску mTLS-сервер.
type Server struct {
	cfg       Config
	tlsConfig *tls.Config
	logger    *log.Logger

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// New перевіряє налаштування, завантажує сертифікати і повертає сервер.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = ":8443"
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	tlsConfig, err := pki.ServerConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:       cfg,
		tlsConfig: tlsConfig,
		logger:    cfg.Logger,
		conns:     make(map[net.Conn]struct{}),
	}, nil
}

// Listen відкриває TLS-слухач. Винесено окремо, щоб у тестах можна було
// взяти адресу з портом, який призначила ОС (:0).
func (s *Server) Listen() (net.Listener, error) {
	ln, err := tls.Listen("tcp", s.cfg.Addr, s.tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("gateway: відкриття слухача %s: %w", s.cfg.Addr, err)
	}
	s.logger.Printf("[СЕРВЕР] Слухач mTLS відкрито на %s", ln.Addr())
	return ln, nil
}

// ListenAndServe — зручний варіант для main: відкрити слухач і одразу
// обслуговувати з'єднання до скасування контексту.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := s.Listen()
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve приймає з'єднання, доки не буде скасовано ctx або закрито слухач.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	var wg sync.WaitGroup
	done := make(chan struct{})

	// Коректне завершення: за сигналом Ctrl+C закриваємо слухач і всі
	// активні з'єднання, щоб не тримати процес живим.
	go func() {
		select {
		case <-ctx.Done():
			s.closeAll()
			_ = ln.Close()
		case <-done:
		}
	}()
	defer close(done)
	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("gateway: прийом з'єднання: %w", err)
		}

		if !s.track(conn) {
			_ = conn.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.untrack(conn)
			s.handleConn(ctx, conn)
		}()
	}
}

// handleConn обслуговує одне з'єднання: TLS-рукостискання, аудит клієнта,
// читання алерту, виклик notifier та відповідь.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		s.logger.Printf("[ПОМИЛКА] очікувався *tls.Conn, отримано %T", conn)
		return
	}

	_ = tlsConn.SetDeadline(time.Now().Add(s.cfg.ReadTimeout))

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		// Найважливіша гілка безпеки: клієнт без валідного сертифіката
		// відсікається ще до читання будь-яких даних.
		s.logger.Printf("[ВІДМОВА] TLS-рукостискання відхилено (%s): %v", conn.RemoteAddr(), err)
		return
	}

	state := tlsConn.ConnectionState()
	identity, err := pki.PeerIdentity(state)
	if err != nil {
		s.logger.Printf("[ВІДМОВА] не вдалося прочитати сертифікат клієнта (%s): %v", conn.RemoteAddr(), err)
		return
	}

	s.logger.Printf("[ПІДКЛЮЧЕННЯ] Встановлено TLS-з'єднання від %s (%s)", conn.RemoteAddr(), pki.TLSVersionName(state.Version))
	s.logger.Printf("[АУДИТ ZERO TRUST] Клієнт верифікований: %s", identity)

	message, err := readMessage(tlsConn)
	if err != nil {
		s.logger.Printf("[ПОМИЛКА] читання повідомлення від %s: %v", conn.RemoteAddr(), err)
		return
	}
	if message == "" {
		s.logger.Printf("[ПОМИЛКА] порожнє повідомлення від %s — ігнорую", conn.RemoteAddr())
		return
	}

	alert := Alert{
		Message:    message,
		ReceivedAt: time.Now(),
		Client:     identity,
		RemoteAddr: conn.RemoteAddr().String(),
		TLSVersion: pki.TLSVersionName(state.Version),
	}
	s.logger.Printf("[ПОВІДОМЛЕННЯ] Отримано інцидент: %s", message)

	reply := ReplyVerified
	if s.cfg.Notifier != nil {
		if err := s.cfg.Notifier(ctx, alert); err != nil {
			s.logger.Printf("[ПОМИЛКА] не вдалося обробити сповіщення: %v", err)
			reply = ReplyDispatchFailed
		} else {
			reply = ReplyDispatched
		}
	}

	_ = tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(tlsConn, "%s\r\n", reply); err != nil {
		s.logger.Printf("[ПОМИЛКА] надсилання відповіді %s: %v", conn.RemoteAddr(), err)
		return
	}
	s.logger.Printf("[ВІДПОВІДЬ] Клієнту надіслано статус: %s", reply)
}

// readMessage читає один рядок (до \n) з обмеженням розміру.
func readMessage(conn net.Conn) (string, error) {
	reader := bufio.NewReader(io.LimitReader(conn, maxMessageSize+1))
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if len(line) > maxMessageSize {
		return "", fmt.Errorf("повідомлення перевищує %d байт", maxMessageSize)
	}
	return strings.TrimSpace(line), nil
}

func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) untrack(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for conn := range s.conns {
		_ = conn.Close()
	}
}
