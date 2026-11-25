package notify_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"secure-alert-gateway/internal/devsmtp"
	"secure-alert-gateway/internal/gateway"
	"secure-alert-gateway/internal/mailer"
	"secure-alert-gateway/internal/notify"
	"secure-alert-gateway/internal/pki"
)

// TestNotifySendsHTMLAndAttachment перевіряє наскрізний сценарій:
// Alert -> HTML + звіт аудиту -> MIME -> SMTP -> .eml.
func TestNotifySendsHTMLAndAttachment(t *testing.T) {
	server, err := devsmtp.Start("127.0.0.1:0", t.TempDir(), log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("запуск devsmtp: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	m, err := mailer.New(mailer.Config{Addr: server.Addr()})
	if err != nil {
		t.Fatalf("mailer.New: %v", err)
	}
	notifier := notify.New(m, "alerts@internal.net", []string{"duty-engineer@internal.net"}, log.New(io.Discard, "", 0))

	receivedAt := time.Date(2026, 11, 25, 22, 30, 0, 0, time.UTC)
	alert := gateway.Alert{
		Message:    "CRITICAL_ERROR: Database connection timeout on node-04",
		ReceivedAt: receivedAt,
		RemoteAddr: "127.0.0.1:54321",
		TLSVersion: "TLS 1.3",
		Client: pki.Identity{
			CommonName: "dispatcher-agent-01",
			Serial:     "1234567890",
			SerialHex:  "499602d2",
			NotBefore:  receivedAt.Add(-time.Hour),
			NotAfter:   receivedAt.Add(365 * 24 * time.Hour),
			Issuer:     "Secure Alert Gateway Root CA",
		},
	}

	if err := notifier.Notify(context.Background(), alert); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	msgs := server.Messages()
	if len(msgs) != 1 {
		t.Fatalf("очікували 1 лист, отримали %d", len(msgs))
	}

	msg, err := mail.ReadMessage(bytes.NewReader(msgs[0].Data))
	if err != nil {
		t.Fatalf("розбір листа: %v", err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatalf("декодування Subject: %v", err)
	}
	if !strings.Contains(subject, "CRITICAL") || !strings.Contains(subject, "node-04") {
		t.Errorf("Subject = %q", subject)
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("Content-Type = %q (%v)", mediaType, err)
	}
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		t.Fatalf("читання тіла: %v", err)
	}
	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])

	htmlPart, err := reader.NextPart()
	if err != nil {
		t.Fatalf("HTML-частина: %v", err)
	}
	htmlBody, err := io.ReadAll(htmlPart)
	if err != nil {
		t.Fatalf("читання HTML: %v", err)
	}
	html, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(htmlBody), "\r\n", ""))
	if err != nil {
		t.Fatalf("Base64 HTML: %v", err)
	}
	if !bytes.Contains(html, []byte("dispatcher-agent-01")) {
		t.Error("в HTML немає CN клієнта")
	}
	if !bytes.Contains(html, []byte("Database connection timeout")) {
		t.Error("в HTML немає тексту інциденту")
	}

	filePart, err := reader.NextPart()
	if err != nil {
		t.Fatalf("частина вкладення: %v", err)
	}
	_, dispParams, err := mime.ParseMediaType(filePart.Header.Get("Content-Disposition"))
	if err != nil {
		t.Fatalf("Content-Disposition: %v", err)
	}
	if dispParams["filename"] != "incident_report.log" {
		t.Errorf("filename = %q", dispParams["filename"])
	}
	reportBody, err := io.ReadAll(filePart)
	if err != nil {
		t.Fatalf("читання вкладення: %v", err)
	}
	report, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(reportBody), "\r\n", ""))
	if err != nil {
		t.Fatalf("Base64 вкладення: %v", err)
	}
	for _, want := range []string{"INCIDENT AUDIT REPORT", "CN=dispatcher-agent-01", "SHA-256"} {
		if !bytes.Contains(report, []byte(want)) {
			t.Errorf("у звіті аудиту немає %q", want)
		}
	}
}
