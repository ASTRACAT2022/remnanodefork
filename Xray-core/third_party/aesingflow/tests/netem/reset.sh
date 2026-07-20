#!/bin/sh
set -eu
dev=${1:-eth0}; sudo tc qdisc del dev "$dev" root 2>/dev/null || true
