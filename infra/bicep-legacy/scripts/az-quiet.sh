#!/usr/bin/env bash
# Ejecuta un comando de az sin que su error llegue al log público de Actions (T9b, THR-019,
# CTL-021). Los errores de ARM llevan IDs de suscripción, nombres de recursos y rangos; aquí solo
# se muestra el código de error (p. ej. InvalidTemplateDeployment), nunca el mensaje.
#
# Uso: az-quiet.sh <fichero-stdout> <comando> [argumentos...]
#   <fichero-stdout>  dónde guardar la salida estándar si el comando va bien (/dev/null si no hace
#                     falta). Si falla, el fichero se vacía.
#
# Sale con el código del comando. Nunca imprime su salida ni su error.
set -uo pipefail

if [[ $# -lt 2 ]]; then
  echo "uso: az-quiet.sh <fichero-stdout> <comando> [argumentos...]" >&2
  exit 2
fi

out_file="$1"
shift

# Etiqueta del comando: solo las palabras iniciales en minúsculas (az deployment group validate),
# nunca los valores de los argumentos.
label=""
for word in "$@"; do
  [[ "$word" =~ ^[a-z][a-z-]{0,30}$ ]] || break
  label="${label:+$label }$word"
done

err_file="$(mktemp "${RUNNER_TEMP:-${TMPDIR:-.}}/az-quiet.XXXXXX")"
trap 'rm -f "$err_file"' EXIT

"$@" >"$out_file" 2>"$err_file"
rc=$?
if [[ $rc -eq 0 ]]; then
  exit 0
fi

# Formatos de az: «(Code) mensaje» al principio de la línea (con o sin «ERROR: »), «Code: X» y
# JSON con "code": "X". Solo se aceptan nombres de código (letras, cifras y punto), nunca el texto
# que los rodea. Un paréntesis en mitad del mensaje no cuenta: podría ser un nombre de recurso.
codes="$(
  grep -oE '^(ERROR: )?\([A-Za-z][A-Za-z0-9.]{1,80}\)|^[[:space:]]*Code: ?[A-Za-z][A-Za-z0-9.]{1,80}|"code": ?"[A-Za-z][A-Za-z0-9.]{1,80}"' "$err_file" \
    | sed -E 's/^(ERROR: )//' \
    | grep -oE '[A-Za-z][A-Za-z0-9.]{1,80}' \
    | grep -vxE 'Code|code' \
    | sort -u \
    | paste -sd, -
)"
: >"$out_file"

echo "::error::${label:-comando} falló (salida $rc). Código: ${codes:-desconocido}. El detalle no se muestra porque los logs son públicos."
exit "$rc"
