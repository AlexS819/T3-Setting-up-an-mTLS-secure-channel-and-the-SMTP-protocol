// Command gencerts генерує локальний ланцюжок довіри для практичної роботи:
// Root CA, серверний сертифікат (localhost/127.0.0.1) і клієнтський
// сертифікат агента диспетчеризації.
//
// Генерація виконана мовою Go (crypto/x509), а не через openssl, щоб
// проєкт однаково працював на Windows, Linux і macOS без сторонніх програм.
// Еквівалентний openssl-скрипт лежить у scripts/generate_certs.sh.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"secure-alert-gateway/internal/pki"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ПОМИЛКА: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dir := flag.String("dir", "certs", "каталог, куди записати сертифікати й ключі")
	days := flag.Int("days", 365, "термін дії сертифікатів, днів")
	serverCN := flag.String("server-cn", "localhost", "CN серверного сертифіката")
	clientCN := flag.String("client-cn", "dispatcher-agent-01", "CN клієнтського сертифіката")
	hosts := flag.String("hosts", "localhost,127.0.0.1,::1", "SAN серверного сертифіката через кому")
	force := flag.Bool("force", false, "перезаписати наявні сертифікати")
	flag.Parse()

	opts := pki.DefaultOptions(*dir)
	opts.Days = *days
	opts.ServerCN = *serverCN
	opts.ClientCN = *clientCN
	opts.ServerHosts = splitAndTrim(*hosts)

	if err := checkExists(opts.Dir, *force); err != nil {
		return err
	}

	if err := pki.Generate(opts); err != nil {
		return err
	}

	fmt.Printf("=== Генерація PKI завершена: %s ===\n", opts.Dir)
	for _, name := range []string{pki.CAFile, pki.ServerCertFile, pki.ClientCertFile} {
		path := filepath.Join(opts.Dir, name)
		info, err := pki.ReadCertificate(path)
		if err != nil {
			return err
		}
		fmt.Printf("  %-12s %s\n", name+":", info)
		if sans := append(append([]string(nil), info.DNSNames...), info.IPAddresses...); len(sans) > 0 {
			fmt.Printf("  %-12s SAN: %s\n", "", strings.Join(sans, ", "))
		}
	}
	fmt.Println("\nФайли закритих ключів (ca.key, server.key, client.key) не можна")
	fmt.Println("передавати третім особам і не слід комітити в Git.")
	fmt.Println("\nДалі: go run ./cmd/gateway   (в іншому терміналі: go run ./cmd/agent)")
	return nil
}

// checkExists не дає випадково перезаписати робочий CA: усі сертифікати,
// які вже видані, стануть недійсними.
func checkExists(dir string, force bool) error {
	if force {
		return nil
	}
	for _, name := range []string{pki.CAFile, pki.CAKeyFile, pki.ServerCertFile, pki.ClientCertFile} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("файл %s вже існує; використайте -force, щоб перезаписати", path)
		}
	}
	return nil
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
