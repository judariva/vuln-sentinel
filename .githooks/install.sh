#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Instala los hooks locales del repo. Uso: bash .githooks/install.sh
# Copia .githooks/pre-push.sh a .git/hooks/pre-push. El hook instalado no se versiona.
# Si ya existe un pre-push distinto, no lo pisa: lo deja como pre-push.bak-<fecha> y avisa.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
hooks_dir="$(git rev-parse --git-path hooks)"
src="$root/.githooks/pre-push.sh"
dst="$hooks_dir/pre-push"

mkdir -p "$hooks_dir"
if [[ -f "$dst" ]] && ! cmp -s "$src" "$dst"; then
  backup="$dst.bak-$(date +%Y%m%d%H%M%S)"
  mv "$dst" "$backup"
  echo "install: había un pre-push distinto; guardado en $backup"
fi
install -m 0755 "$src" "$dst"
echo "install: pre-push instalado en $dst (bloquea push a: ${VS_PROTECTED_BRANCHES:-main})"
