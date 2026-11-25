#!/usr/bin/env bash
# Генерація локального PKI для Secure Alert Gateway через openssl.
# Використання: ./scripts/generate_certs.sh [каталог]
# За замовчуванням сертифікати пишуться в ./certs.
#
# Цей скрипт — «класичний» варіант із завдання. Основний генератор проєкту
# (cmd/gencerts) робить те саме мовою Go і не потребує openssl.
set -euo pipefail

DIR="${1:-certs}"
DAYS="${DAYS:-365}"

if ! command -v openssl >/dev/null 2>&1; then
    echo "ПОМИЛКА: openssl не знайдено в PATH" >&2
    exit 1
fi

mkdir -p "$DIR"
cd "$DIR"

if [ -e "ca.key" ] && [ "${FORCE:-0}" != "1" ]; then
    echo "ПОМИЛКА: $DIR/ca.key вже існує. Використайте FORCE=1, щоб перезаписати." >&2
    exit 1
fi

# 1. Кореневий центр сертифікації (самопідписаний, 10 років було б краще,
#    але для лабораторної достатньо року).
openssl genrsa -out ca.key 2048 2>/dev/null
openssl req -x509 -new -key ca.key -sha256 -days "$DAYS" -out ca.crt \
    -subj "/CN=Secure Alert Gateway Root CA/O=Secure Alert Gateway Lab" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"

# 2. Серверний сертифікат із SAN localhost / 127.0.0.1 / ::1.
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -out server.csr \
    -subj "/CN=localhost/O=Secure Alert Gateway Lab"

cat > server.ext <<'EOF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days "$DAYS" -sha256 -extfile server.ext 2>/dev/null

# 3. Клієнтський сертифікат агента диспетчеризації.
openssl genrsa -out client.key 2048 2>/dev/null
openssl req -new -key client.key -out client.csr \
    -subj "/CN=dispatcher-agent-01/O=Secure Alert Gateway Lab"

cat > client.ext <<'EOF'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days "$DAYS" -sha256 -extfile client.ext 2>/dev/null

# Прибираємо тимчасові файли, щоб у каталозі залишились лише потрібні.
rm -f server.csr client.csr server.ext client.ext ca.srl

echo "=== PKI згенеровано в $DIR ==="
openssl x509 -in ca.crt -noout -subject -dates
openssl x509 -in server.crt -noout -subject -ext subjectAltName
openssl x509 -in client.crt -noout -subject -ext extendedKeyUsage
