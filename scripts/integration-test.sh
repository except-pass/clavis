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

echo "=== Remove ==="
./clavis rm prod/influx.port
./clavis rm dev/mysql

echo ""
echo "=== All tests passed ==="
