package mailer

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net/mail"
	"path/filepath"
	"strings"
	"time"
)

// Message — лист, який треба надіслати. HTML — тіло листа, Attachment —
// необов'язковий вкладений файл (у нашому випадку звіт аудиту).
type Message struct {
	From           string
	To             []string
	Subject        string
	HTML           string
	AttachmentName string
	Attachment     []byte
}

// BuildMIME збирає повний лист multipart/mixed: HTML-частина та, за
// наявності, вкладений файл у Base64. Усі рядки завершуються CRLF,
// як вимагає RFC 5322.
func BuildMIME(msg Message) ([]byte, error) {
	from, err := mail.ParseAddress(msg.From)
	if err != nil {
		return nil, fmt.Errorf("mailer: некоректна адреса відправника %q: %w", msg.From, err)
	}
	if len(msg.To) == 0 {
		return nil, errors.New("mailer: не вказано жодного отримувача")
	}
	to := make([]string, 0, len(msg.To))
	for _, raw := range msg.To {
		addr, err := mail.ParseAddress(raw)
		if err != nil {
			return nil, fmt.Errorf("mailer: некоректна адреса отримувача %q: %w", raw, err)
		}
		to = append(to, formatAddress(addr))
	}
	if err := checkHeaderValue("Subject", msg.Subject); err != nil {
		return nil, err
	}
	if msg.AttachmentName != "" {
		if err := checkHeaderValue("ім'я вкладення", msg.AttachmentName); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(msg.HTML) == "" {
		return nil, errors.New("mailer: порожнє тіло листа")
	}

	boundary, err := newBoundary()
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	writeHeader := func(name, value string) {
		fmt.Fprintf(&b, "%s: %s\r\n", name, value)
	}

	writeHeader("From", formatAddress(from))
	writeHeader("To", strings.Join(to, ", "))
	// Тему кодуємо у RFC 2047, інакше кирилиця в заголовку буде "кракозябрами".
	writeHeader("Subject", mime.QEncoding.Encode("UTF-8", msg.Subject))
	writeHeader("Date", time.Now().Format(time.RFC1123Z))
	writeHeader("MIME-Version", "1.0")
	writeHeader("Content-Type", fmt.Sprintf("multipart/mixed; boundary=%q", boundary))
	b.WriteString("\r\n")

	// Частина 1: HTML-тіло.
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("\r\n")
	writeBase64(&b, []byte(msg.HTML))

	// Частина 2: вкладений файл (за бажанням).
	if len(msg.Attachment) > 0 {
		name := msg.AttachmentName
		if name == "" {
			name = "attachment.bin"
		}
		contentType := mime.TypeByExtension(filepath.Ext(name))
		params := map[string]string{"name": name}
		if contentType == "" {
			// .log і .txt — звичайний текст, його краще показувати одразу
			// в поштовому клієнті, а не пропонувати як "невідомий файл".
			if ext := strings.ToLower(filepath.Ext(name)); ext == ".log" || ext == ".txt" {
				contentType = "text/plain"
				params["charset"] = "UTF-8"
			} else {
				contentType = "application/octet-stream"
			}
		}

		fmt.Fprintf(&b, "--%s\r\n", boundary)
		// mime.FormatMediaType сам лапкує ім'я та кодує не-ASCII за RFC 2231.
		fmt.Fprintf(&b, "Content-Type: %s\r\n", mime.FormatMediaType(contentType, params))
		fmt.Fprintf(&b, "Content-Disposition: %s\r\n",
			mime.FormatMediaType("attachment", map[string]string{"filename": name}))
		b.WriteString("Content-Transfer-Encoding: base64\r\n")
		b.WriteString("\r\n")
		writeBase64(&b, msg.Attachment)
	}

	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}

// writeBase64 записує дані в Base64 рядками по 76 символів.
// Обмеження довжини рядка взяте з RFC 2045: довші рядки деякі SMTP-сервери
// можуть обрізати або відхилити.
func writeBase64(b *bytes.Buffer, data []byte) {
	encoded := base64.StdEncoding.EncodeToString(data)
	const lineLength = 76
	for len(encoded) > lineLength {
		b.WriteString(encoded[:lineLength])
		b.WriteString("\r\n")
		encoded = encoded[lineLength:]
	}
	if len(encoded) > 0 {
		b.WriteString(encoded)
		b.WriteString("\r\n")
	}
}

// formatAddress повертає адресу для заголовка. Якщо імені немає, кутові
// дужки не потрібні: "alerts@internal.net" читається краще, ніж "<...>".
func formatAddress(addr *mail.Address) string {
	if addr.Name == "" {
		return addr.Address
	}
	return addr.String()
}

// checkHeaderValue захищає від injection: символи CR/LF у заголовку
// дозволили б дописати довільні поля (наприклад, приховану копію Bcc).
func checkHeaderValue(field, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("mailer: поле %q містить символи переведення рядка", field)
	}
	return nil
}

func newBoundary() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("mailer: генерація boundary: %w", err)
	}
	return "==SecureAlertGateway_" + hex.EncodeToString(buf), nil
}
