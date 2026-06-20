#!/usr/bin/env bash
# Run the permission-system test suite (behaviour tests + rule validation).
# Usage: ./run.sh
set -euo pipefail
cd "$(dirname "$0")"
node --test --experimental-strip-types \
  permissions.test.ts \
  validate.test.ts
