#!/bin/bash

set -u

echo "=== Thesis detection cycle started ==="

status=0

echo "Running M03..."
/usr/bin/python3 /usr/local/bin/thesis_m03_counter.py || status=1

echo "Running M04..."
/usr/bin/python3 /usr/local/bin/thesis_m04_counter.py || status=1

echo "=== Thesis detection cycle completed ==="

exit "$status"
