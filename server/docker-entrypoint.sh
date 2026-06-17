#!/bin/sh
# SOC Xpert entrypoint — aplica migrações e seed quando há base de dados,
# caso contrário arranca em modo legado (.env / demo). Nunca bloqueia o arranque.
set -e

if [ -n "$DATABASE_URL" ]; then
  echo "[entrypoint] DATABASE_URL detetado — a preparar base de dados..."
  n=0
  until npx prisma migrate deploy; do
    n=$((n + 1))
    if [ "$n" -ge 10 ]; then
      echo "[entrypoint] migração falhou após 10 tentativas — a arrancar em modo degradado."
      break
    fi
    echo "[entrypoint] base de dados ainda não pronta — nova tentativa em 3s ($n/10)..."
    sleep 3
  done

  if [ "${RUN_SEED:-true}" = "true" ]; then
    echo "[entrypoint] a executar seed (idempotente)..."
    node dist/seed.js || echo "[entrypoint] aviso: seed não concluído — a continuar."
  fi
else
  echo "[entrypoint] sem DATABASE_URL — modo legado (.env / demo), sem base de dados."
fi

exec "$@"
