// Command agent — авторизований mTLS-клієнт (агент диспетчеризації).
// Він пред'являє серверу свій сертифікат, перевіряє сертифікат сервера
// за локальним Root CA та надсилає повідомлення про інцидент.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"secure-alert-gateway/internal/pki"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	if err := run(logger); err != nil {
		logger.Printf("[КЛІЄНТ] ПОМИЛКА: %v", err)
		os.Exit(1)
	}
}

func run(logger *log.Logger) error {
	var (
		addr       = flag.String("addr", "127.0.0.1:8443", "адреса mTLS-шлюзу")
		certDir    = flag.String("certs", "certs", "каталог із client.crt, client.key, ca.crt")
		message    = flag.String("msg", "CRITICAL_ERROR: Database connection timeout on node-04", "текст алерту")
		serverName = flag.String("server-name", "", "очікуване ім'я сервера в сертифікаті (за замовчуванням — хост з адреси)")
		timeout    = flag.Duration("timeout", 10*time.Second, "таймаут підключення")
		noCert     = flag.Bool("no-cert", false, "демонстрація: підключитися БЕЗ клієнтського сертифіката (сервер має відмовити)")
	)
	flag.Parse()

	certFile := filepath.Join(*certDir, pki.ClientCertFile)
	keyFile := filepath.Join(*certDir, pki.ClientKeyFile)
	caFile := filepath.Join(*certDir, pki.CAFile)

	fmt.Println("=== Агент диспетчеризації (mTLS Client) ===")

	var tlsConfig *tls.Config
	var err error

	if *noCert {
		// Навмисно "поганий" клієнт: довіряє серверу, але не має власного
		// сертифіката. Використовується лише для демонстрації відмови.
		logger.Printf("[КЛІЄНТ] РЕЖИМ БЕЗ СЕРТИФІКАТА: клієнтський сертифікат не пред'являється")
		pool, _, poolErr := pki.LoadCAPool(caFile)
		if poolErr != nil {
			return poolErr
		}
		tlsConfig = &tls.Config{
			RootCAs:    pool,
			ServerName: *serverName,
			MinVersion: tls.VersionTLS12,
		}
	} else {
		identity, readErr := pki.ReadCertificate(certFile)
		if readErr != nil {
			return fmt.Errorf("%w\nпідказка: спочатку виконайте `go run ./cmd/gencerts`", readErr)
		}
		logger.Printf("[КЛІЄНТ] Завантажено сертифікат клієнта: %s (CN=%s)", certFile, identity.CommonName)
		tlsConfig, err = pki.ClientConfig(certFile, keyFile, caFile, *serverName)
		if err != nil {
			return err
		}
	}

	logger.Printf("[КЛІЄНТ] Підключення до шлюзу %s...", *addr)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: *timeout},
		Config:    tlsConfig,
	}
	conn, err := dialer.DialContext(ctx, "tcp", *addr)
	if err != nil {
		if *noCert {
			return fmt.Errorf("сервер відхилив підключення без клієнтського сертифіката: %w", err)
		}
		return fmt.Errorf("mTLS-рукостискання не вдалося: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(*timeout)); err != nil {
		return err
	}

	if *noCert {
		// У TLS 1.3 клієнт може вважати рукостискання завершеним раніше,
		// ніж отримає відмову сервера. Тому чекаємо на перше читання:
		// саме тут прийде alert "certificate required".
		_, readErr := bufio.NewReader(conn).ReadString('\n')
		if readErr != nil {
			return fmt.Errorf("сервер розірвав з'єднання без клієнтського сертифіката: %w", readErr)
		}
		return errors.New("неочікувано: сервер прийняв клієнта без сертифіката")
	}

	state := conn.(*tls.Conn).ConnectionState()
	logger.Printf("[КЛІЄНТ] mTLS-рукостискання успішне. Використано протокол %s", pki.TLSVersionName(state.Version))
	logger.Printf("[КЛІЄНТ] Сертифікат сервера перевірено за %s", caFile)

	logger.Printf("[КЛІЄНТ] Відправка алерту: %s", *message)
	if _, err := fmt.Fprintf(conn, "%s\r\n", *message); err != nil {
		return fmt.Errorf("відправка алерту: %w", err)
	}

	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("очікування відповіді від сервера: %w", err)
	}
	logger.Printf("[КЛІЄНТ] Відповідь від сервера: %s", trimNewline(reply))
	logger.Printf("[КЛІЄНТ] Сесію успішно завершено.")
	return nil
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
