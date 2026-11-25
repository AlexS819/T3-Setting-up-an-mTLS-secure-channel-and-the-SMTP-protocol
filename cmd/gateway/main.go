// Command gateway — консольний шлюз критичних сповіщень.
//
// Він слухає mTLS-порт, приймає алерти лише від клієнтів із сертифікатом
// спільного Root CA, фіксує ідентичність клієнта (аудит Zero Trust)
// і надсилає HTML-лист зі звітом аудиту черговому інженеру через SMTP.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"secure-alert-gateway/internal/gateway"
	"secure-alert-gateway/internal/mailer"
	"secure-alert-gateway/internal/notify"
	"secure-alert-gateway/internal/pki"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	if err := run(logger); err != nil {
		logger.Printf("КРИТИЧНА ПОМИЛКА: %v", err)
		os.Exit(1)
	}
}

func run(logger *log.Logger) error {
	var (
		addr      = flag.String("addr", ":8443", "адреса mTLS-слухача")
		certDir   = flag.String("certs", "certs", "каталог із ca.crt, server.crt, server.key")
		smtpAddr  = flag.String("smtp-addr", envOr("ALERT_SMTP_ADDR", "127.0.0.1:1025"), "адреса SMTP-сервера host:port")
		smtpHost  = flag.String("smtp-host", "", "ім'я SMTP-сервера для EHLO/STARTTLS (за замовчуванням — хост зі smtp-addr)")
		smtpUser  = flag.String("smtp-user", os.Getenv("SMTP_USER"), "логін SMTP (порожній — без авторизації)")
		smtpPass  = flag.String("smtp-pass", "", "пароль SMTP (краще задавати через SMTP_PASSWORD)")
		mailFrom  = flag.String("mail-from", envOr("ALERT_MAIL_FROM", "alerts@internal.net"), "адреса відправника")
		mailTo    = flag.String("mail-to", envOr("ALERT_MAIL_TO", "duty-engineer@internal.net"), "отримувачі через кому")
		noEmail   = flag.Bool("no-email", false, "режим Рівня 1: не надсилати пошту, лише підтвердити прийом")
		readLimit = flag.Duration("read-timeout", 10*time.Second, "таймаут очікування повідомлення від клієнта")
	)
	flag.Parse()

	if *smtpPass == "" {
		*smtpPass = os.Getenv("SMTP_PASSWORD")
	}

	caFile := filepath.Join(*certDir, pki.CAFile)
	certFile := filepath.Join(*certDir, pki.ServerCertFile)
	keyFile := filepath.Join(*certDir, pki.ServerKeyFile)

	// Завантажуємо CA окремо лише для того, щоб показати кількість
	// сертифікатів у пулі довіри на старті (і зрозуміло впасти, якщо файлу немає).
	_, caCount, err := pki.LoadCAPool(caFile)
	if err != nil {
		return fmt.Errorf("%w\nпідказка: спочатку виконайте `go run ./cmd/gencerts`", err)
	}

	fmt.Printf("=== Захищений шлюз критичних сповіщень (mTLS: %s, SMTP Target: %s) ===\n", *addr, *smtpAddr)
	logger.Printf("[СЕРВЕР] Пул CA завантажено: %s (%d %s)", caFile, caCount, pluralCerts(caCount))

	cfg := gateway.Config{
		Addr:        *addr,
		CertFile:    certFile,
		KeyFile:     keyFile,
		CAFile:      caFile,
		ReadTimeout: *readLimit,
		Logger:      logger,
	}

	if *noEmail {
		logger.Printf("[СЕРВЕР] Режим без пошти: працює лише mTLS-прийом (Рівень 1)")
	} else {
		m, err := mailer.New(mailer.Config{
			Addr:     *smtpAddr,
			Host:     *smtpHost,
			Username: *smtpUser,
			Password: *smtpPass,
		})
		if err != nil {
			return err
		}
		recipients := splitAndTrim(*mailTo)
		if len(recipients) == 0 {
			return fmt.Errorf("не вказано жодного отримувача (прапорець -mail-to)")
		}
		notifier := notify.New(m, *mailFrom, recipients, logger)
		logger.Printf("[СЕРВЕР] Поштові сповіщення увімкнено: %s -> %s", *mailFrom, strings.Join(recipients, ", "))

		// Шлюз не має «зависати» на SMTP: кожна спроба обмежена таймаутом.
		cfg.Notifier = func(ctx context.Context, alert gateway.Alert) error {
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			return notifier.Notify(ctx, alert)
		}
	}

	server, err := gateway.New(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Printf("[СЕРВЕР] Готовий приймати алерти. Ctrl+C — зупинити.")
	if err := server.ListenAndServe(ctx); err != nil {
		return err
	}
	logger.Printf("[СЕРВЕР] Шлюз зупинено.")
	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func splitAndTrim(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// pluralCerts узгоджує слово з числом: 1 сертифікат, 2 сертифікати, 5 сертифікатів.
func pluralCerts(n int) string {
	switch {
	case n%100 >= 11 && n%100 <= 14:
		return "сертифікатів"
	case n%10 == 1:
		return "сертифікат"
	case n%10 >= 2 && n%10 <= 4:
		return "сертифікати"
	default:
		return "сертифікатів"
	}
}
