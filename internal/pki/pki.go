// Package pki містить усе, що стосується інфраструктури відкритих ключів (PKI):
// генерацію локального Root CA, серверного та клієнтського сертифікатів,
// завантаження TLS-конфігурацій і читання ідентичності клієнта з сертифіката.
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Імена файлів, які створює генератор PKI. Вони ж використовуються
// шлюзом і клієнтом за замовчуванням.
const (
	CAFile         = "ca.crt"
	CAKeyFile      = "ca.key"
	ServerCertFile = "server.crt"
	ServerKeyFile  = "server.key"
	ClientCertFile = "client.crt"
	ClientKeyFile  = "client.key"

	keyBits = 2048
)

// Identity — людське подання сертифіката, яке ми показуємо в логах,
// у листі-сповіщенні та у звіті аудиту.
type Identity struct {
	CommonName  string
	Serial      string // серійний номер у десятковому вигляді
	SerialHex   string // той самий номер у шістнадцятковому вигляді
	NotBefore   time.Time
	NotAfter    time.Time
	Issuer      string
	DNSNames    []string
	IPAddresses []string
}

// String повертає короткий рядок для логу.
func (i Identity) String() string {
	return fmt.Sprintf("CN=%s, Серійний номер=%s, дійсний до %s",
		i.CommonName, i.Serial, i.NotAfter.Format("2006-01-02 15:04:05 MST"))
}

// Options описує параметри генерації локального ланцюжка довіри.
type Options struct {
	Dir         string   // каталог, куди будуть записані ca.crt, server.crt тощо
	Days        int      // термін дії сертифікатів у днях
	CAName      string   // CN кореневого сертифіката
	ServerCN    string   // CN серверного сертифіката
	ClientCN    string   // CN клієнтського сертифіката (ідентичність агента)
	ServerHosts []string // значення для SAN: DNS-імена та IP-адреси
}

// DefaultOptions повертає параметри, що відповідають завданню практичної роботи.
func DefaultOptions(dir string) Options {
	return Options{
		Dir:         dir,
		Days:        365,
		CAName:      "Secure Alert Gateway Root CA",
		ServerCN:    "localhost",
		ClientCN:    "dispatcher-agent-01",
		ServerHosts: []string{"localhost", "127.0.0.1", "::1"},
	}
}

// Generate створює повний ланцюжок довіри: Root CA -> server, Root CA -> client.
// Ключі зберігаються у форматі PKCS#8, сертифікати — у PEM.
func Generate(opts Options) error {
	if opts.Dir == "" {
		return errors.New("pki: не вказано каталог для сертифікатів")
	}
	if opts.Days <= 0 {
		opts.Days = 365
	}
	if opts.CAName == "" {
		opts.CAName = "Secure Alert Gateway Root CA"
	}
	if opts.ServerCN == "" {
		opts.ServerCN = "localhost"
	}
	if opts.ClientCN == "" {
		opts.ClientCN = "dispatcher-agent-01"
	}
	if len(opts.ServerHosts) == 0 {
		opts.ServerHosts = []string{"localhost", "127.0.0.1", "::1"}
	}

	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return fmt.Errorf("pki: створення каталогу %s: %w", opts.Dir, err)
	}

	notBefore := time.Now().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(opts.Days) * 24 * time.Hour)

	// 1. Кореневий центр сертифікації (самопідписаний сертифікат).
	caKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return fmt.Errorf("pki: генерація ключа CA: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          newSerialNumber(),
		Subject:               pkix.Name{CommonName: opts.CAName, Organization: []string{"Secure Alert Gateway Lab"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          randomBytes(20),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("pki: створення сертифіката CA: %w", err)
	}
	// Після створення PEM сертифікат треба розпарсити: x509.CreateCertificate
	// не заповнює поля похідного об'єкта (зокрема SubjectKeyId).
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fmt.Errorf("pki: розбір сертифіката CA: %w", err)
	}
	if err := writeCert(filepath.Join(opts.Dir, CAFile), caDER); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(opts.Dir, CAKeyFile), caKey); err != nil {
		return err
	}

	// 2. Серверний сертифікат із SAN localhost/127.0.0.1/::1.
	if err := generateLeaf(opts, caCert, caKey, leafSpec{
		cn:       opts.ServerCN,
		certFile: ServerCertFile,
		keyFile:  ServerKeyFile,
		hosts:    opts.ServerHosts,
		usage:    x509.ExtKeyUsageServerAuth,
	}); err != nil {
		return err
	}

	// 3. Клієнтський сертифікат, яким агент доводить свою ідентичність.
	if err := generateLeaf(opts, caCert, caKey, leafSpec{
		cn:       opts.ClientCN,
		certFile: ClientCertFile,
		keyFile:  ClientKeyFile,
		usage:    x509.ExtKeyUsageClientAuth,
	}); err != nil {
		return err
	}

	return nil
}

type leafSpec struct {
	cn       string
	certFile string
	keyFile  string
	hosts    []string
	usage    x509.ExtKeyUsage
}

// generateLeaf створює ключ і сертифікат кінцевого вузла, підписаний CA.
func generateLeaf(opts Options, caCert *x509.Certificate, caKey *rsa.PrivateKey, spec leafSpec) error {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return fmt.Errorf("pki: генерація ключа для %s: %w", spec.cn, err)
	}

	template := &x509.Certificate{
		SerialNumber:          newSerialNumber(),
		Subject:               pkix.Name{CommonName: spec.cn, Organization: []string{"Secure Alert Gateway Lab"}},
		NotBefore:             caCert.NotBefore,
		NotAfter:              caCert.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{spec.usage},
		BasicConstraintsValid: true,
		AuthorityKeyId:        caCert.SubjectKeyId,
	}

	if spec.usage == x509.ExtKeyUsageServerAuth {
		// KeyEncipherment потрібен для TLS 1.2 з RSA-обміном ключами,
		// для TLS 1.3 він не використовується, але зайвим не буде.
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
		for _, host := range spec.hosts {
			if ip := net.ParseIP(host); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, host)
			}
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("pki: підпис сертифіката %s: %w", spec.cn, err)
	}
	if err := writeCert(filepath.Join(opts.Dir, spec.certFile), der); err != nil {
		return err
	}
	return writeKey(filepath.Join(opts.Dir, spec.keyFile), key)
}

// LoadCAPool читає PEM-файл із одним або кількома сертифікатами
// та повертає пул довіри разом із кількістю завантажених сертифікатів.
func LoadCAPool(path string) (*x509.CertPool, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("pki: читання %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, 0, fmt.Errorf("pki: у файлі %s не знайдено жодного сертифіката PEM", path)
	}
	return pool, len(pool.Subjects()), nil
}

// ServerConfig збирає tls.Config для шлюзу: свій сертифікат плюс вимога
// пред'явити клієнтський сертифікат, підписаний нашим CA.
func ServerConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("pki: завантаження серверної пари %s/%s: %w", certFile, keyFile, err)
	}
	pool, _, err := LoadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// Головний перемикач mTLS: без валідного клієнтського сертифіката
		// рукостискання не завершиться.
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		// TLS 1.2 залишаємо як мінімум для сумісності з промисловими
		// клієнтами; TLS 1.3 узгоджується автоматично і його видно в логах.
		MinVersion: tls.VersionTLS12,
	}, nil
}

// ClientConfig збирає tls.Config для агента: свій сертифікат для сервера
// та пул довіри для перевірки сертифіката шлюзу.
func ClientConfig(certFile, keyFile, caFile, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("pki: завантаження клієнтської пари %s/%s: %w", certFile, keyFile, err)
	}
	pool, _, err := LoadCAPool(caFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ReadCertificate повертає Identity для першого сертифіката у PEM-файлі.
func ReadCertificate(path string) (Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, fmt.Errorf("pki: читання %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return Identity{}, fmt.Errorf("pki: %s не містить PEM-сертифіката", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Identity{}, fmt.Errorf("pki: розбір %s: %w", path, err)
	}
	return identityFromCert(cert), nil
}

// PeerIdentity дістає сертифікат клієнта зі стану вже встановленого
// TLS-з'єднання. Саме тут реалізується "аудит Zero Trust".
func PeerIdentity(state tls.ConnectionState) (Identity, error) {
	if len(state.PeerCertificates) == 0 {
		return Identity{}, errors.New("pki: клієнт не пред'явив сертифікат")
	}
	return identityFromCert(state.PeerCertificates[0]), nil
}

// TLSVersionName повертає людську назву версії протоколу для логів.
func TLSVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS (0x%04x)", v)
	}
}

func identityFromCert(cert *x509.Certificate) Identity {
	identity := Identity{
		CommonName: cert.Subject.CommonName,
		Serial:     cert.SerialNumber.String(),
		SerialHex:  cert.SerialNumber.Text(16),
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		Issuer:     cert.Issuer.CommonName,
		DNSNames:   cert.DNSNames,
	}
	for _, ip := range cert.IPAddresses {
		identity.IPAddresses = append(identity.IPAddresses, ip.String())
	}
	return identity
}

func newSerialNumber() *big.Int {
	// 128 випадкових бітів — достатньо, щоб серійні номери не повторювались.
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil || serial.Sign() == 0 {
		// crypto/rand практично не падає; якщо це сталось — краще впасти явно.
		panic("pki: не вдалося згенерувати серійний номер: " + fmt.Sprint(err))
	}
	return serial
}

func randomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("pki: не вдалося згенерувати випадкові байти: " + err.Error())
	}
	return buf
}

func writeCert(path string, der []byte) error {
	return writePEM(path, "CERTIFICATE", der, 0o644)
}

func writeKey(path string, key *rsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("pki: серіалізація ключа %s: %w", path, err)
	}
	return writePEM(path, "PRIVATE KEY", der, 0o600)
}

func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("pki: відкриття %s: %w", path, err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		return fmt.Errorf("pki: запис %s: %w", path, err)
	}
	return nil
}
