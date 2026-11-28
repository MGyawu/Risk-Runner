#!/usr/bin/env bash
# Copies the data from the old Postgres container (the pre-RDS docker-compose.aws.yml) into RDS.
# Runs on the EC2 instance as the ubuntu user, from the app directory. The Deploy to AWS workflow
# runs it through SSM before deploying the RDS version of the app; it can also be run by hand.
#
# Safe to run any number of times. It does nothing when:
#   - RDS already has Risk Runner tables (already migrated, or the new app already started), or
#   - there's no old database container (a fresh install).
# The old container and its volume are left as they are, so rolling back stays possible.
set -euo pipefail

PREFIX="${PARAM_PREFIX:-/risk-runner}"
APP_DIR="${APP_DIR:-$HOME/Risk-Runner}"
DUMP="${DUMP_FILE:-$HOME/risk_runner-$(date +%Y%m%d-%H%M%S).dump}"
PG_IMAGE="${PG_IMAGE:-postgres:17}"
cd "$APP_DIR"

if [ -n "${RISK_RUNNER_DATABASE_URL:-}" ]; then
  url="$RISK_RUNNER_DATABASE_URL"
else
  url="$(aws ssm get-parameter --with-decryption --name "$PREFIX/RISK_RUNNER_DATABASE_URL" \
    --query Parameter.Value --output text)"
fi
PGURL="${url/+psycopg/}"  # libpq doesn't understand SQLAlchemy's driver suffix

psql_rds() { docker run --rm -i --network host "$PG_IMAGE" psql "$PGURL" -v ON_ERROR_STOP=1 -At "$@"; }

if [ "$(psql_rds -c "select to_regclass('public.findings') is not null")" = t ]; then
  echo "RDS already has Risk Runner tables; nothing to migrate."
  exit 0
fi

old="$(docker ps -q --filter label=com.docker.compose.service=db --filter status=running | head -n1)"
if [ -z "$old" ]; then
  echo "No old database container is running; nothing to migrate (fresh install)."
  exit 0
fi

count() { echo "select 'repositories', count(*) from repositories union all select 'findings', count(*) from findings union all select 'scans', count(*) from scans;"; }

echo "Dumping the old database to $DUMP"
umask 077
docker exec "$old" pg_dump -U risk -d risk_runner -Fc > "$DUMP"
ls -lh "$DUMP"

echo "Restoring into RDS (one transaction: a failure leaves RDS empty, so a rerun tries again)"
docker run --rm -i --network host "$PG_IMAGE" pg_restore --no-owner --no-privileges --single-transaction -d "$PGURL" < "$DUMP"

echo "Row counts (old | RDS):"
paste -d'|' <(docker exec "$old" psql -U risk -d risk_runner -At -c "$(count)") <(psql_rds -c "$(count)")
if [ "$(docker exec "$old" psql -U risk -d risk_runner -At -c "$(count)")" != "$(psql_rds -c "$(count)")" ]; then
  echo "WARNING: row counts differ. A scan probably arrived during the copy; rerun that scan after the deploy."
fi
echo "Migrated. The old container and its volume are untouched; the dump is at $DUMP."
