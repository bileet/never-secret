#!/bin/sh
# Make a throwaway folder inside the current project, fill it with dummy secrets and print
# only its path. Values are random per run and never printed, so the agent can only learn
# them by reading the files.
set -e
rnd() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }

mkdir -p tmp
d=$(mktemp -d tmp/neversecret-check.XXXXXX)

# known secret file: every value is hidden by format
cat >"$d/.env" <<EOF
DB_HOST=db.internal
DB_PASSWORD=$(rnd 20)
STRIPE_KEY=sk_live_$(rnd 24)
EOF

# known secret file: whole-file redaction
cat >"$d/id_rsa" <<EOF
-----BEGIN OPENSSH PRIVATE KEY-----
$(rnd 64)
$(rnd 64)
-----END OPENSSH PRIVATE KEY-----
EOF

# ordinary source file: secrets must be found by pattern/detection
cat >"$d/settings.py" <<EOF
DEBUG = True
GITHUB_TOKEN = "ghp_$(rnd 36)"
OPENAI_API_KEY = "sk-$(rnd 40)"
EOF

echo "$d"
