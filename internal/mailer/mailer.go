package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"time"
)

// Config — параметри підключення до SMTP-сервера.
type Config struct {
	Addr     string        // host:port, наприклад 127.0.0.1:1025
	Host     string        // ім'я для EHLO/STARTTLS; за замовчуванням береться з Addr
	Username string        // порожній рядок — сервер без авторизації (Mailpit/MailHog)
	Password string        // пароль застосунку; краще передавати через змінну середовища
	Timeout  time.Duration // таймаут на весь діалог зі SMTP-сервером
}

// Mailer надсилає листи. Один екземпляр можна використовувати з різних
// горутин: у ньому немає спільного змінного стану.
type Mailer struct {
	cfg Config
}

// New перевіряє конфігурацію і створює Mailer.
func New(cfg Config) (*Mailer, error) {
	if cfg.Addr == "" {
		return nil, errors.New("mailer: не вказано адресу SMTP-сервера")
	}
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("mailer: некоректна адреса SMTP %q: %w", cfg.Addr, err)
	}
	if cfg.Host == "" {
		cfg.Host = host
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	return &Mailer{cfg: cfg}, nil
}

// Addr повертає адресу SMTP-сервера (потрібна для логів).
func (m *Mailer) Addr() string { return m.cfg.Addr }

// Send формує MIME-лист і передає його SMTP-серверу.
// Використовується smtp.Client (пакет net/smtp), а не smtp.SendMail, щоб
// контролювати таймаути, контекст і політику STARTTLS.
func (m *Mailer) Send(ctx context.Context, msg Message) error {
	raw, err := BuildMIME(msg)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{Timeout: m.cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", m.cfg.Addr)
	if err != nil {
		return fmt.Errorf("mailer: підключення до SMTP %s: %w", m.cfg.Addr, err)
	}

	deadline := time.Now().Add(m.cfg.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mailer: SMTP-привітання: %w", err)
	}
	defer client.Close()

	// Якщо сервер вміє STARTTLS — обов'язково підвищуємо канал до TLS.
	// Пароль у відкритому вигляді не передаємо ніколи.
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{
			ServerName: m.cfg.Host,
			MinVersion: tls.VersionTLS12,
		}); err != nil {
			return fmt.Errorf("mailer: STARTTLS: %w", err)
		}
	} else if m.cfg.Username != "" {
		return errors.New("mailer: сервер не підтримує STARTTLS, авторизацію скасовано (пароль не можна слати відкритим текстом)")
	}

	if m.cfg.Username != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("mailer: SMTP-авторизація: %w", err)
		}
	}

	if err := client.Mail(msg.From); err != nil {
		return fmt.Errorf("mailer: команда MAIL FROM: %w", err)
	}
	for _, rcpt := range msg.To {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("mailer: команда RCPT TO <%s>: %w", rcpt, err)
		}
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("mailer: команда DATA: %w", err)
	}
	if _, err := writer.Write(raw); err != nil {
		_ = writer.Close()
		return fmt.Errorf("mailer: передача листа: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("mailer: завершення листа: %w", err)
	}

	if err := client.Quit(); err != nil {
		return fmt.Errorf("mailer: QUIT: %w", err)
	}
	return nil
}
