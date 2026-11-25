// Command devsmtp — локальний SMTP-емулятор для демонстрації без Docker.
// Приймає листи та зберігає їх у каталог tmp/mail як .eml-файли.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"secure-alert-gateway/internal/devsmtp"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	if err := run(logger); err != nil {
		logger.Printf("КРИТИЧНА ПОМИЛКА: %v", err)
		os.Exit(1)
	}
}

func run(logger *log.Logger) error {
	addr := flag.String("addr", "127.0.0.1:1025", "адреса SMTP-слухача")
	out := flag.String("out", "tmp/mail", "каталог для збереження .eml-файлів")
	flag.Parse()

	server, err := devsmtp.Start(*addr, *out, logger)
	if err != nil {
		return err
	}
	defer server.Close()

	fmt.Printf("=== devsmtp: локальний SMTP-емулятор на %s ===\n", server.Addr())
	fmt.Printf("Листи зберігаються у: %s\n", *out)
	fmt.Println("Ctrl+C — зупинити.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	logger.Printf("[DEVSMTP] Зупинка. Прийнято листів: %d", len(server.Messages()))
	return nil
}
