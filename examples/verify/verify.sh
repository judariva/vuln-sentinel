#!/usr/bin/env bash
# Verifica la firma de un documento del feed de vuln-sentinel solo con openssl y coreutils.
#
# Uso: verify.sh DOCUMENTO DOCUMENTO.jws CLAVE_PUBLICA.pem
#
# La firma es un JWS detached ES256 (RFC 7797, b64=false): "<cabecera>..<firma>".
# Entrada firmada = "<cabecera en base64url>" + "." + bytes exactos del documento.
# La firma JWS es r||s (64 bytes); openssl espera DER, así que se convierte con asn1parse.
# La clave PEM se obtiene del JWKS con: python3 verify.py --pem KID keys.json > clave.pem
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "uso: $0 DOCUMENTO DOCUMENTO.jws CLAVE_PUBLICA.pem" >&2
  exit 2
fi
doc=$1
jws_file=$2
pub=$3

fail() { echo "FIRMA NO VÁLIDA: $*"; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/vs-verify.XXXXXX")
trap 'rm -rf "$work"' EXIT

b64url_decode() {
  local s
  s=$(printf '%s' "$1" | tr '_-' '/+')
  case $(( ${#s} % 4 )) in
    2) s="$s==" ;;
    3) s="$s=" ;;
    1) return 1 ;;
  esac
  printf '%s' "$s" | base64 -d
}

jws=$(tr -d ' \r\n' < "$jws_file")
protected=${jws%%.*}
rest=${jws#*.}
payload_part=${rest%%.*}
signature=${rest#*.}
[ -n "$protected" ] && [ -n "$signature" ] || fail "JWS mal formado"
[ -z "$payload_part" ] || fail "no es un JWS con payload separado"

header=$(b64url_decode "$protected") || fail "cabecera no es base64url"
case "$header" in *'"alg":"ES256"'*) ;; *) fail "alg distinto de ES256" ;; esac
case "$header" in *'"b64":false'*) ;; *) fail "falta b64=false" ;; esac
case "$header" in *'"crit":["b64"]'*) ;; *) fail "falta crit=[\"b64\"]" ;; esac

# Entrada firmada (RFC 7797, §3)
{ printf '%s.' "$protected"; cat "$doc"; } > "$work/input"

b64url_decode "$signature" > "$work/sig.raw" || fail "firma no es base64url"
[ "$(wc -c < "$work/sig.raw")" -eq 64 ] || fail "firma ES256 de longitud incorrecta"
hex=$(od -An -v -tx1 "$work/sig.raw" | tr -d ' \n')
printf 'asn1=SEQUENCE:sig\n[sig]\nr=INTEGER:0x%s\ns=INTEGER:0x%s\n' \
  "${hex:0:64}" "${hex:64:64}" > "$work/sig.cnf"
openssl asn1parse -genconf "$work/sig.cnf" -out "$work/sig.der" -noout

if openssl dgst -sha256 -verify "$pub" -signature "$work/sig.der" "$work/input"; then
  exit 0
fi
fail "openssl rechaza la firma"
