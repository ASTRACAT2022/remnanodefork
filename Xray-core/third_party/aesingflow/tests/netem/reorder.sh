#!/bin/sh
set -eu
dev=${1:-eth0}; sudo tc qdisc replace dev "$dev" root netem delay 20ms reorder 5% 50%
