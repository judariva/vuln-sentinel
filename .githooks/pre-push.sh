#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Hook pre-push: rechaza cualquier push que actualice o borre la rama protegida (por defecto, main).
# Regla de CLAUDE.md (J-8): ninguna sesión hace push a main; solo ramas y PR; fusiona Juan.
# Se instala con .githooks/install.sh (copia a .git/hooks/pre-push; el hook instalado no se versiona).
#
# Git pasa por stdin una línea por ref: <local ref> <local sha> <remote ref> <remote sha>
set -euo pipefail

PROTECTED="${VS_PROTECTED_BRANCHES:-main}"

blocked=0
while read -r local_ref _local_sha remote_ref _remote_sha; do
  [[ -z "${remote_ref:-}" ]] && continue
  for branch in $PROTECTED; do
    if [[ "$remote_ref" == "refs/heads/$branch" ]]; then
      echo "pre-push: BLOQUEADO push a '$branch' (desde '${local_ref}')." >&2
      echo "pre-push: los cambios entran por rama y PR; fusiona Juan (CLAUDE.md, regla J-8)." >&2
      blocked=1
    fi
  done
done

exit "$blocked"
