package mailer

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

func decodePart(t *testing.T, part *multipart.Part) []byte {
	t.Helper()
	body, err := io.ReadAll(part)
	if err != nil {
		t.Fatalf("читання частини: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(body), "\r\n", ""))
	if err != nil {
		t.Fatalf("Base64-декодування частини: %v", err)
	}
	return decoded
}

func TestBuildMIME(t *testing.T) {
	attachment := []byte("=== INCIDENT AUDIT REPORT ===\nCN=dispatcher-agent-01\n\x00\x01\x02")
	html := `<p>Аварія: <b>CN=dispatcher-agent-01</b></p>`

	raw, err := BuildMIME(Message{
		From:           "alerts@internal.net",
		To:             []string{"duty-engineer@internal.net", "shift-lead@internal.net"},
		Subject:        "Аварія на node-04",
		HTML:           html,
		AttachmentName: "incident_report.log",
		Attachment:     attachment,
	})
	if err != nil {
		t.Fatalf("BuildMIME: %v", err)
	}

	// 1. Заголовки листа мають бути коректними з точки зору net/mail.
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("лист не парситься: %v", err)
	}
	if got := msg.Header.Get("MIME-Version"); got != "1.0" {
		t.Errorf("MIME-Version = %q, очікували 1.0", got)
	}
	if got := msg.Header.Get("From"); got != "alerts@internal.net" {
		t.Errorf("From = %q", got)
	}
	if got := msg.Header.Get("To"); !strings.Contains(got, "duty-engineer@internal.net") {
		t.Errorf("To = %q", got)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil {
		t.Fatalf("декодування Subject: %v", err)
	}
	if subject != "Аварія на node-04" {
		t.Errorf("Subject = %q", subject)
	}

	// 2. Структура multipart/mixed.
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("Content-Type: %v", err)
	}
	if mediaType != "multipart/mixed" {
		t.Fatalf("Content-Type = %q, очікували multipart/mixed", mediaType)
	}
	boundary := params["boundary"]
	if boundary == "" {
		t.Fatal("у Content-Type відсутній boundary")
	}

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		t.Fatalf("читання тіла: %v", err)
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)

	// 3. Перша частина — HTML.
	htmlPart, err := reader.NextPart()
	if err != nil {
		t.Fatalf("перша частина: %v", err)
	}
	if got := htmlPart.Header.Get("Content-Type"); got != "text/html; charset=UTF-8" {
		t.Errorf("HTML Content-Type = %q", got)
	}
	if got := string(decodePart(t, htmlPart)); got != html {
		t.Errorf("HTML-тіло відрізняється:\nотримано: %q", got)
	}

	// 4. Друга частина — вкладений файл.
	filePart, err := reader.NextPart()
	if err != nil {
		t.Fatalf("друга частина: %v", err)
	}
	_, dispParams, err := mime.ParseMediaType(filePart.Header.Get("Content-Disposition"))
	if err != nil {
		t.Fatalf("Content-Disposition: %v", err)
	}
	if dispParams["filename"] != "incident_report.log" {
		t.Errorf("filename = %q", dispParams["filename"])
	}
	if got := decodePart(t, filePart); !bytes.Equal(got, attachment) {
		t.Errorf("вкладення пошкоджене: %q", got)
	}

	// 5. Зайвих частин немає.
	if _, err := reader.NextPart(); err != io.EOF {
		t.Errorf("очікували кінець MIME, отримали %v", err)
	}
}

func TestBuildMIMEWithoutAttachment(t *testing.T) {
	raw, err := BuildMIME(Message{
		From:    "alerts@internal.net",
		To:      []string{"duty-engineer@internal.net"},
		Subject: "Без вкладення",
		HTML:    "<p>ok</p>",
	})
	if err != nil {
		t.Fatalf("BuildMIME: %v", err)
	}
	if bytes.Contains(raw, []byte("Content-Disposition: attachment")) {
		t.Error("у листі без вкладення з'явився Content-Disposition: attachment")
	}
}

func TestBuildMIMEValidatesInput(t *testing.T) {
	base := Message{
		From:    "alerts@internal.net",
		To:      []string{"duty-engineer@internal.net"},
		Subject: "Тема",
		HTML:    "<p>ok</p>",
	}

	tests := []struct {
		name   string
		mutate func(m *Message)
	}{
		{"порожній список отримувачів", func(m *Message) { m.To = nil }},
		{"некоректний отримувач", func(m *Message) { m.To = []string{"не-адреса"} }},
		{"порожнє тіло", func(m *Message) { m.HTML = "  " }},
		{"ін'єкція заголовка в тему", func(m *Message) { m.Subject = "Тема\r\nBcc: evil@example.com" }},
		{"ін'єкція у назву вкладення", func(m *Message) {
			m.AttachmentName = "log.txt\r\nX-Evil: 1"
			m.Attachment = []byte("data")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := base
			tt.mutate(&msg)
			if _, err := BuildMIME(msg); err == nil {
				t.Fatal("очікували помилку валідації, але її немає")
			}
		})
	}
}
