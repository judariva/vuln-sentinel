#!/usr/bin/env bash
# Verifica la firma de un documento del feed de vuln-sentinel solo con openssl y coreutils.
#
# Uso: verify.sh [--expected-thumbprint HUELLA]... DOCUMENTO DOCUMENTO.jws CLAVE_PUBLICA.pem
#
# La firma es un JWS detached ES256 (RFC 7797, b64=false): "<cabecera>..<firma>".
# Entrada firmada = "<cabecera en base64url>" + "." + bytes exactos del documento.
# La firma JWS es r||s (64 bytes); openssl espera DER, así que se convierte con asn1parse.
# La clave PEM se obtiene del JWKS con: python3 verify.py --pem KID keys.json > clave.pem
#
# --expected-thumbprint (se puede repetir): huella RFC 7638 de una clave en la que confías,
# publicada fuera del origen (docs/feed/keys.md del repo y notas de release). Se calcula aquí a
# partir de la PEM; si no coincide con ninguna, falla. Sin ella, la clave no está fijada.
set -euo pipefail

usage() {
  echo "uso: $0 [--expected-thumbprint HUELLA]... DOCUMENTO DOCUMENTO.jws CLAVE_PUBLICA.pem" >&2
  exit 2
}

expected=()
pinning=0
while [ "$#" -gt 0 ]; do
  case $1 in
    --expected-thumbprint)
      [ "$#" -ge 2 ] || usage
      pinning=1
      [ -n "$2" ] && expected+=("$2")
      shift 2
      ;;
    --expected-thumbprint=*)
      pinning=1
      [ -n "${1#*=}" ] && expected+=("${1#*=}")
      shift
      ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done
[ "$#" -eq 3 ] || usage
[ "$pinning" -eq 0 ] || [ "${#expected[@]}" -gt 0 ] || usage
doc=$1
jws_file=$2
pub=$3

fail() { echo "FIRMA NO VÁLIDA: $*"; exit 1; }

work=$(mktemp -d "${TMPDIR:-/tmp}/vs-verify.XXXXXX")
trap 'rm -rf "$work"' EXIT

b64url_encode() { base64 | tr -d '\n=' | tr '+/' '-_'; }

# Huella RFC 7638 de una clave pública EC P-256 en PEM.
thumbprint() {
  local der=$work/spki.der x y
  openssl ec -pubin -in "$1" -pubout -conv_form uncompressed -outform DER -out "$der" \
    2> /dev/null || return 1
  # SubjectPublicKeyInfo de P-256: 26 bytes fijos, 0x04 y luego x e y de 32 bytes.
  [ "$(wc -c < "$der")" -eq 91 ] || return 1
  [ "$(head -c 27 "$der" | od -An -v -tx1 | tr -d ' \n')" = \
    "3059301306072a8648ce3d020106082a8648ce3d03010703420004" ] || return 1
  x=$(tail -c +28 "$der" | head -c 32 | b64url_encode)
  y=$(tail -c 32 "$der" | b64url_encode)
  printf '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' "$x" "$y" \
    | openssl dgst -sha256 -binary | b64url_encode
}

if [ "$pinning" -eq 1 ]; then
  tp=$(thumbprint "$pub") || fail "la clave no es EC P-256"
  match=0
  for want in "${expected[@]}"; do
    [ "$tp" = "$want" ] && match=1
  done
  [ "$match" -eq 1 ] || fail "la clave no tiene ninguna huella esperada ($tp)"
fi

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
# El kid tiene que ser una cadena no vacía (con la PEM no se busca en el JWKS, pero se exige igual).
kid_re='"kid":"([^"]+)"'
[[ $header =~ $kid_re ]] || fail "kid ausente, vacío o que no es una cadena"

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
