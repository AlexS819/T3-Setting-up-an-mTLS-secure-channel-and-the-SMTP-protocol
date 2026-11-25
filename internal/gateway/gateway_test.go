package gateway_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"secure-alert-gateway/internal/gateway"
	"secure-alert-gateway/internal/pki"
)

// testGateway — піднятий у тесті шлюз разом із каталогом його PKI.
type testGateway struct {
	addr    string
	certDir string
	alerts  *[]gateway.Alert
	mu      *sync.Mutex
}

// newTestServer генерує тимчасовий PKI і запускає шлюз на вільному порту.
func newTestServer(t *testing.T) *testGateway {
	t.Helper()

	dir := t.TempDir()
	if err := pki.Generate(pki.DefaultOptions(dir)); err != nil {
		t.Fatalf("генерація PKI: %v", err)
	}

	var mu sync.Mutex
	received := &[]gateway.Alert{}

	server, err := gateway.New(gateway.Config{
		Addr:     "127.0.0.1:0",
		CertFile: filepath.Join(dir, pki.ServerCertFile),
		KeyFile:  filepath.Join(dir, pki.ServerKeyFile),
		CAFile:   filepath.Join(dir, pki.CAFile),
		Logger:   log.New(io.Discard, "", 0),
		Notifier: func(_ context.Context, alert gateway.Alert) error {
			mu.Lock()
			defer mu.Unlock()
			*received = append(*received, alert)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}

	ln, err := server.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve не завершився за 5 секунд")
		}
	})

	return &testGateway{addr: ln.Addr().String(), certDir: dir, alerts: received, mu: &mu}
}

// clientConfig збирає конфігурацію клієнта з указаного каталогу PKI.
func (g *testGateway) clientConfig(t *testing.T, certDir, serverName string) *tls.Config {
	t.Helper()
	cfg, err := pki.ClientConfig(
		filepath.Join(certDir, pki.ClientCertFile),
		filepath.Join(certDir, pki.ClientKeyFile),
		filepath.Join(certDir, pki.CAFile),
		serverName,
	)
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	return cfg
}

// TestMTLSFlow — основний сценарій: валідний клієнт отримує підтвердження,
// а шлюз фіксує CN, серійний номер і версію TLS із захищеного з'єднання.
func TestMTLSFlow(t *testing.T) {
	g := newTestServer(t)

	conn, err := tls.Dial("tcp", g.addr, g.clientConfig(t, g.certDir, "localhost"))
	if err != nil {
		t.Fatalf("підключення валідного клієнта: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("CRITICAL_ERROR: Database connection timeout on node-04\r\n")); err != nil {
		t.Fatalf("запис алерту: %v", err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("читання відповіді: %v", err)
	}
	if got := strings.TrimSpace(reply); got != gateway.ReplyDispatched {
		t.Errorf("відповідь = %q, очікували %q", got, gateway.ReplyDispatched)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if len(*g.alerts) != 1 {
		t.Fatalf("шлюз обробив %d алертів, очікували 1", len(*g.alerts))
	}
	alert := (*g.alerts)[0]
	if alert.Client.CommonName != "dispatcher-agent-01" {
		t.Errorf("CN = %q", alert.Client.CommonName)
	}
	if alert.Client.Serial == "" || alert.Client.SerialHex == "" {
		t.Error("не зафіксовано серійний номер сертифіката")
	}
	if !strings.Contains(alert.Message, "Database connection timeout") {
		t.Errorf("повідомлення = %q", alert.Message)
	}
	if alert.TLSVersion == "" {
		t.Error("не зафіксовано версію TLS")
	}
	if alert.RemoteAddr == "" {
		t.Error("не зафіксовано адресу клієнта")
	}
}

// TestClientWithoutCertificateRejected — ключова перевірка Рівня 1:
// клієнт без сертифіката відсікається ще на рукостисканні.
func TestClientWithoutCertificateRejected(t *testing.T) {
	g := newTestServer(t)

	pool, _, err := pki.LoadCAPool(filepath.Join(g.certDir, pki.CAFile))
	if err != nil {
		t.Fatalf("LoadCAPool: %v", err)
	}
	conn, err := tls.Dial("tcp", g.addr, &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		// У TLS 1.3 клієнт завершує свою частину рукостискання раніше,
		// ніж отримає відмову сервера. Тому відмову бачимо на першому
		// читанні/записі, а не обов'язково на tls.Dial.
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.Write([]byte("CRITICAL_ERROR: no certificate\r\n"))
		_, err = bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("сервер прийняв клієнта без сертифіката")
	}
	t.Logf("рукостискання відхилено, як і очікувалось: %v", err)

	g.mu.Lock()
	defer g.mu.Unlock()
	if len(*g.alerts) != 0 {
		t.Errorf("шлюз обробив алерт від неавторизованого клієнта")
	}
}

// TestClientFromForeignCARejected — сертифікат підписаний стороннім CA,
// хоча серверу цей клієнт довіряє (RootCAs правильні).
func TestClientFromForeignCARejected(t *testing.T) {
	g := newTestServer(t)

	foreignDir := t.TempDir()
	if err := pki.Generate(pki.DefaultOptions(foreignDir)); err != nil {
		t.Fatalf("генерація стороннього PKI: %v", err)
	}
	foreignCert, err := tls.LoadX509KeyPair(
		filepath.Join(foreignDir, pki.ClientCertFile),
		filepath.Join(foreignDir, pki.ClientKeyFile),
	)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	pool, _, err := pki.LoadCAPool(filepath.Join(g.certDir, pki.CAFile))
	if err != nil {
		t.Fatalf("LoadCAPool: %v", err)
	}

	conn, err := tls.Dial("tcp", g.addr, &tls.Config{
		Certificates: []tls.Certificate{foreignCert},
		RootCAs:      pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	})
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.Write([]byte("CRITICAL_ERROR: foreign CA\r\n"))
		_, err = bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("сервер прийняв клієнта зі стороннім CA")
	}
	t.Logf("клієнт зі стороннім CA відхилений: %v", err)

	g.mu.Lock()
	defer g.mu.Unlock()
	if len(*g.alerts) != 0 {
		t.Error("шлюз обробив алерт від клієнта зі стороннім CA")
	}
}

// TestPlainTCPRejected — незашифрований TCP-клієнт не може передати алерт.
func TestPlainTCPRejected(t *testing.T) {
	g := newTestServer(t)

	conn, err := net.Dial("tcp", g.addr)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	_, _ = conn.Write([]byte("CRITICAL_ERROR: plaintext injection\r\n"))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if strings.Contains(string(buf[:n]), "ALERT") {
		t.Error("сервер обробив незашифрований запит як алерт")
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if len(*g.alerts) != 0 {
		t.Error("шлюз обробив незашифрований запит")
	}
}
