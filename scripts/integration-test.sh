#!/bin/bash
set -e

export HOME=/tmp/clavis-integration-test-$$
rm -rf $HOME/.secrets
trap "rm -rf $HOME" EXIT

echo "=== Initialize ==="
./clavis init

echo "=== Add secrets ==="
./clavis add prod/influx username=admin password=secret123 url=https://influx.example.com --tag env:prod --tag service:influx
./clavis add dev/mysql username=root password=devpass --tag env:dev --tag service:mysql

echo "=== List ==="
./clavis list
./clavis list env:prod
./clavis list --tags

echo "=== Get ==="
./clavis get prod/influx
./clavis get prod/influx.password
./clavis get prod/influx --format=json

echo "=== Set ==="
./clavis set prod/influx port=8086
./clavis show prod/influx

echo "=== Tag ==="
./clavis tag dev/mysql team:backend
./clavis list team:backend

echo "=== Files output ==="
./clavis get prod/influx --format=files --output=$HOME/secrets-test
ls -la $HOME/secrets-test/

echo "=== Lock / Unlock ==="
./clavis add lock/a secret=aaa --tag env:prod --tag service:influx
./clavis add lock/b secret=bbb --tag env:dev

# Lock a single secret; it must become unreadable while its sibling stays readable.
./clavis lock lock/a --password testpw
if ./clavis get lock/a.secret >/dev/null 2>&1; then
    echo "FAIL: locked secret was still readable"
    exit 1
fi
echo "locked secret correctly blocked"
./clavis get lock/b.secret >/dev/null
echo "unlocked sibling still readable"

# The padlock shows only next to the locked secret.
./clavis list

# Unlock restores access.
./clavis unlock lock/a --password testpw
./clavis get lock/a.secret >/dev/null
echo "unlocked secret readable again"

# Bulk lock by tag: env:prod is locked, env:dev is untouched.
./clavis lock --tag env:prod --password testpw
if ./clavis get lock/a.secret >/dev/null 2>&1; then
    echo "FAIL: tag-locked secret was still readable"
    exit 1
fi
./clavis get lock/b.secret >/dev/null
echo "bulk tag lock works, non-matching secret untouched"

# Unlock everything.
./clavis unlock --all --password testpw
./clavis get lock/a.secret >/dev/null
echo "unlock --all works"

# A locked secret must not leak through other read paths.
./clavis lock lock/a --password testpw
if ./clavis search --reveal aaa | grep -q aaa; then
    echo "FAIL: search --reveal exposed a locked secret value"
    exit 1
fi
echo "search --reveal does not expose locked values"
if ./clavis edit lock/a >/dev/null 2>&1; then
    echo "FAIL: edit opened a locked secret"
    exit 1
fi
echo "edit refuses a locked secret"

# Removing the last locked secret must not orphan the shared password:
# a fresh lock afterward should set a brand-new password.
./clavis rm lock/a
./clavis lock lock/b --password brandnewpw
./clavis get lock/b.secret >/dev/null 2>&1 && { echo "FAIL: lock/b readable while locked"; exit 1; }
./clavis unlock lock/b --password brandnewpw
echo "rm of last locked secret does not orphan the lock password"

./clavis rm lock/b

echo "=== Remove ==="
./clavis rm prod/influx.port
./clavis rm dev/mysql

echo ""
echo "=== All tests passed ==="
