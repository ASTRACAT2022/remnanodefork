#!/bin/sh
set -eu
dev=${1:-eth0}; sudo tc qdisc replace dev "$dev" root netem loss 10%
