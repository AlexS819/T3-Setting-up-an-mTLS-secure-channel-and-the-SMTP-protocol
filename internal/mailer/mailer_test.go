package mailer_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"strings"
	"testing"

	"secure-alert-gateway/internal/devsmtp"
	"secure-alert-gateway/internal/mailer"
)

// TestSendToDevSMTP перевіряє весь SMTP-діалог: EHLO, MAIL FROM, RCPT TO,
// DATA і передачу MIME-листа без авторизації (як у Mailpit).
func TestSendToDevSMTP(t *testing.T) {
	server, err := devsmtp.Start("127.0.0.1:0", t.TempDir(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("запуск devsmtp: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	m, err := mailer.New(mailer.Config{Addr: server.Addr()})
	if err != nil {
		t.Fatalf("mailer.New: %v", err)
	}

	err = m.Send(context.Background(), mailer.Message{
		From:           "alerts@internal.net",
		To:             []string{"duty-engineer@internal.net"},
		Subject:        "Аварія на node-04",
		HTML:           "<p>Привіт</p>",
		AttachmentName: "incident_report.log",
		Attachment:     []byte("report"),
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	msgs := server.Messages()
	if len(msgs) != 1 {
		t.Fatalf("очікували 1 лист, отримали %d", len(msgs))
	}
	msg := msgs[0]
	if msg.From != "alerts@internal.net" {
		t.Errorf("MAIL FROM = %q", msg.From)
	}
	if len(msg.To) != 1 || msg.To[0] != "duty-engineer@internal.net" {
		t.Errorf("RCPT TO = %v", msg.To)
	}
	if !bytes.Contains(msg.Data, []byte("multipart/mixed")) {
		t.Error("у листі немає multipart/mixed")
	}
	if !bytes.Contains(msg.Data, []byte("incident_report.log")) {
		t.Error("у листі немає назви вкладення")
	}
	if !strings.Contains(string(msg.Data), "Content-Transfer-Encoding: base64") {
		t.Error("немає Base64-кодування")
	}
}

// TestSendRejectsPasswordWithoutTLS перевіряє політику безпеки:
// якщо SMTP не вміє STARTTLS, пароль не відправляється взагалі.
func TestSendRejectsPasswordWithoutTLS(t *testing.T) {
	server, err := devsmtp.Start("127.0.0.1:0", t.TempDir(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("запуск devsmtp: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	m, err := mailer.New(mailer.Config{
		Addr:     server.Addr(),
		Username: "user@internal.net",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("mailer.New: %v", err)
	}

	err = m.Send(context.Background(), mailer.Message{
		From:    "alerts@internal.net",
		To:      []string{"duty-engineer@internal.net"},
		Subject: "Тест",
		HTML:    "<p>ok</p>",
	})
	if err == nil {
		t.Fatal("очікували відмову: сервер не підтримує STARTTLS")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("неочікувана помилка: %v", err)
	}
}
