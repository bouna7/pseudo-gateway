#!/usr/bin/env sh
# Installe le binaire pseudo-gateway (Linux / macOS, x86_64 ou ARM64).
#
#   curl -fsSL https://github.com/bouna7/pseudo-gateway/releases/latest/download/install.sh | sh
#
# Variables : VERSION (ex. v0.2.0, défaut : dernière release),
#             INSTALL_DIR (défaut : $HOME/.local/bin).
set -eu

REPO="bouna7/pseudo-gateway"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux)  os="unknown-linux-musl" ;;
  Darwin) os="apple-darwin" ;;
  *) echo "Système non pris en charge : $(uname -s) (Windows : install.ps1)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch="x86_64" ;;
  aarch64|arm64) arch="aarch64" ;;
  *) echo "Architecture non prise en charge : $(uname -m)" >&2; exit 1 ;;
esac
asset="pseudo-gateway-${arch}-${os}"

if [ -n "${VERSION:-}" ]; then
  base="https://github.com/${REPO}/releases/download/${VERSION}"
else
  base="https://github.com/${REPO}/releases/latest/download"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Téléchargement de ${asset}.tar.gz…"
curl -fsSL -o "$tmp/${asset}.tar.gz" "${base}/${asset}.tar.gz"
curl -fsSL -o "$tmp/SHA256SUMS" "${base}/SHA256SUMS"

expected="$(grep " ${asset}.tar.gz\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/${asset}.tar.gz" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp/${asset}.tar.gz" | cut -d' ' -f1)"
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
  echo "Empreinte SHA-256 invalide — installation annulée." >&2
  exit 1
fi

tar -xzf "$tmp/${asset}.tar.gz" -C "$tmp"
mkdir -p "$INSTALL_DIR"
install -m 755 "$tmp/${asset}/pseudo-gateway" "$INSTALL_DIR/pseudo-gateway"

echo "Installé : $INSTALL_DIR/pseudo-gateway ($("$INSTALL_DIR/pseudo-gateway" --version))"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Ajoutez $INSTALL_DIR à votre PATH pour lancer « pseudo-gateway » directement." ;;
esac
cat <<'EOF'

Démarrage rapide :
  pseudo-gateway gen-keys > .env   # secrets neufs
  pseudo-gateway                   # API sur http://localhost:8080
EOF
