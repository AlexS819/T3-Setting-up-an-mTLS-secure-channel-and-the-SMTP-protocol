// Package notify перетворює прийнятий шлюзом Alert у лист: формує тему,
// HTML-тіло та текстовий звіт аудиту для вкладення, а потім віддає його Mailer.
package notify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"strings"
	"time"

	"secure-alert-gateway/internal/gateway"
	"secure-alert-gateway/internal/mailer"
)

const auditReportName = "incident_report.log"

// Notifier — обробник подій, який шлюз викликає після успішного mTLS-прийому.
type Notifier struct {
	mailer *mailer.Mailer
	from   string
	to     []string
	logger *log.Logger
}

// New створює Notifier. from — адреса відправника, to — список отримувачів
// (у завданні це черговий інженер duty-engineer@internal.net).
func New(m *mailer.Mailer, from string, to []string, logger *log.Logger) *Notifier {
	return &Notifier{mailer: m, from: from, to: to, logger: logger}
}

// Notify формує MIME-лист (HTML + вкладення) та надсилає його.
func (n *Notifier) Notify(ctx context.Context, alert gateway.Alert) error {
	n.logger.Printf("[SMTP] Формування MIME-повідомлення (HTML + вкладення %s)...", auditReportName)

	htmlBody, err := renderHTML(alert)
	if err != nil {
		return fmt.Errorf("notify: формування HTML: %w", err)
	}
	report := renderAuditReport(alert)

	n.logger.Printf("[SMTP] Надсилання email на %s через %s...", strings.Join(n.to, ", "), n.mailer.Addr())

	err = n.mailer.Send(ctx, mailer.Message{
		From:           n.from,
		To:             n.to,
		Subject:        subject(alert),
		HTML:           htmlBody,
		AttachmentName: auditReportName,
		Attachment:     []byte(report),
	})
	if err != nil {
		n.logger.Printf("[SMTP] [FAIL] Помилка доставки: %v", err)
		return err
	}

	n.logger.Printf("[SMTP] [OK] Лист про аварію успішно доставлено до поштового шлюзу!")
	return nil
}

// subject будує коротку тему листа, щоб вона не перевищувала розумну довжину.
func subject(alert gateway.Alert) string {
	short := alert.Message
	if runes := []rune(short); len(runes) > 70 {
		short = string(runes[:70]) + "…"
	}
	return fmt.Sprintf("[CRITICAL] %s | %s", short, alert.ReceivedAt.Format("02.01.2006 15:04:05"))
}

// renderAuditReport формує текстовий звіт, який прикріплюється до листа.
func renderAuditReport(alert gateway.Alert) string {
	sum := sha256.Sum256([]byte(alert.Message))

	var b strings.Builder
	b.WriteString("========================================================\n")
	b.WriteString("       SECURE ALERT GATEWAY — INCIDENT AUDIT REPORT\n")
	b.WriteString("========================================================\n")
	fmt.Fprintf(&b, "Час реєстрації (local): %s\n", alert.ReceivedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "Час реєстрації (UTC):   %s\n", alert.ReceivedAt.UTC().Format(time.RFC3339))
	b.WriteString("--------------------------------------------------------\n")
	fmt.Fprintf(&b, "Автентифікований суб'єкт: CN=%s\n", alert.Client.CommonName)
	fmt.Fprintf(&b, "Серійний номер:           %s (0x%s)\n", alert.Client.Serial, alert.Client.SerialHex)
	fmt.Fprintf(&b, "Видавець:                 %s\n", alert.Client.Issuer)
	fmt.Fprintf(&b, "Дійсний з:                %s\n", alert.Client.NotBefore.Format(time.RFC3339))
	fmt.Fprintf(&b, "Дійсний до:               %s\n", alert.Client.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(&b, "Віддалена адреса:         %s\n", alert.RemoteAddr)
	fmt.Fprintf(&b, "Версія TLS:               %s\n", alert.TLSVersion)
	b.WriteString("--------------------------------------------------------\n")
	fmt.Fprintf(&b, "SHA-256 повідомлення:     %s\n", hex.EncodeToString(sum[:]))
	b.WriteString("Повідомлення про інцидент:\n")
	fmt.Fprintf(&b, "  %s\n", alert.Message)
	b.WriteString("--------------------------------------------------------\n")
	b.WriteString("Висновок: клієнт пройшов взаємну TLS-автентифікацію,\n")
	b.WriteString("сертифікат підписаний довіреним Root CA, подія передана\n")
	b.WriteString("черговій інженерній службі.\n")
	b.WriteString("========================================================\n")
	return b.String()
}

// Шаблон листа. html/template автоматично екранує значення, тому навіть
// шкідливий текст алерту не зламає верстку (XSS у поштовому клієнті).
var htmlTemplate = template.Must(template.New("alert").Funcs(template.FuncMap{
	"timefmt": func(t time.Time) string { return t.Format("02.01.2006 15:04:05") },
	"utc":     func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") },
}).Parse(`<!DOCTYPE html>
<html lang="uk">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:24px;background:#f4f5f7;font-family:Segoe UI,Arial,sans-serif;color:#1f2933;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #d9dde3;border-radius:8px;overflow:hidden;">
    <tr>
      <td style="background:#b3261e;color:#ffffff;padding:16px 24px;">
        <div style="font-size:12px;letter-spacing:1px;text-transform:uppercase;opacity:.85;">Secure Alert Gateway</div>
        <div style="font-size:22px;font-weight:600;margin-top:4px;">🚨 CRITICAL ALERT / АВАРІЯ</div>
      </td>
    </tr>
    <tr>
      <td style="padding:24px;">
        <p style="margin:0 0 16px 0;font-size:15px;">
          Зафіксовано критичну подію. Запит надійшов від верифікованого пристрою
          <b>[CN={{.Client.CommonName}}]</b> через захищений канал mTLS.
        </p>
        <p style="margin:0 0 16px 0;padding:12px 16px;background:#fdecea;border-left:4px solid #b3261e;font-family:Consolas,monospace;font-size:14px;">
          {{.Message}}
        </p>
        <table role="presentation" width="100%" cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:14px;">
          <tr><td style="width:42%;color:#616e7c;border-bottom:1px solid #eceff1;">Час реєстрації</td>
              <td style="border-bottom:1px solid #eceff1;">{{timefmt .ReceivedAt}} ({{utc .ReceivedAt}})</td></tr>
          <tr><td style="color:#616e7c;border-bottom:1px solid #eceff1;">Ідентифікатор із сертифіката</td>
              <td style="border-bottom:1px solid #eceff1;font-family:Consolas,monospace;">CN={{.Client.CommonName}}</td></tr>
          <tr><td style="color:#616e7c;border-bottom:1px solid #eceff1;">Серійний номер</td>
              <td style="border-bottom:1px solid #eceff1;font-family:Consolas,monospace;">{{.Client.Serial}}</td></tr>
          <tr><td style="color:#616e7c;border-bottom:1px solid #eceff1;">Дійсний до</td>
              <td style="border-bottom:1px solid #eceff1;">{{timefmt .Client.NotAfter}}</td></tr>
          <tr><td style="color:#616e7c;border-bottom:1px solid #eceff1;">Віддалена адреса</td>
              <td style="border-bottom:1px solid #eceff1;font-family:Consolas,monospace;">{{.RemoteAddr}}</td></tr>
          <tr><td style="color:#616e7c;border-bottom:1px solid #eceff1;">Протокол</td>
              <td style="border-bottom:1px solid #eceff1;">{{.TLSVersion}}</td></tr>
        </table>
        <p style="margin:20px 0 0 0;font-size:13px;color:#616e7c;">
          До листа додано звіт аудиту <b>{{.ReportName}}</b> (Base64-вкладення).
          Це автоматичне повідомлення, відповідати на нього не потрібно.
        </p>
      </td>
    </tr>
    <tr>
      <td style="background:#f4f5f7;padding:12px 24px;font-size:12px;color:#7b8794;">
        Secure Alert Gateway · Zero Trust / mTLS · {{timefmt .ReceivedAt}}
      </td>
    </tr>
  </table>
</body>
</html>`))

func renderHTML(alert gateway.Alert) (string, error) {
	data := struct {
		gateway.Alert
		ReportName string
	}{Alert: alert, ReportName: auditReportName}

	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
