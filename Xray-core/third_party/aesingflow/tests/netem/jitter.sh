#!/bin/sh
set -eu
dev=${1:-eth0}; sudo tc qdisc replace dev "$dev" root netem delay 100ms 50ms distribution normal
