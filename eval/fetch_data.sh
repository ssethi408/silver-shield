#!/usr/bin/env bash
# Download the two labeled datasets into data/ (ignored by git).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data
curl -fsSL -o data/sms.zip "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
unzip -o -q data/sms.zip -d data
curl -fsSL -o data/texts.json "https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/texts.json"
echo "Downloaded: data/SMSSpamCollection, data/texts.json"
