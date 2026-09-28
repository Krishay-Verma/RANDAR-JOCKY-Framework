#!/usr/bin/env sh
# JOCKY launcher (Linux/macOS). Usage: ./start.sh [--dev] [--new-token] [--rebuild]
cd "$(dirname "$0")" && exec python3 start.py "$@"
