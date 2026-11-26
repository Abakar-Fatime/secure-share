#!/usr/bin/env bash
# Build the API deployment package for AWS Lambda (Python 3.12, arm64).
# Output: build/lambda.zip
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf build/lambda && mkdir -p build/lambda
python -m pip install --quiet \
  --platform manylinux2014_aarch64 --implementation cp --python-version 3.12 \
  --only-binary=:all: --target build/lambda -r backend/requirements.txt
cp -r backend/app build/lambda/app
find build/lambda -name "__pycache__" -type d -prune -exec rm -rf {} +
(cd build/lambda && zip -qr9 ../lambda.zip .)
echo "Built build/lambda.zip ($(du -h build/lambda.zip | cut -f1))"
