#!/bin/sh
# RTT 180 ms, jitter 80 ms, loss 8%, reordering 3%, bandwidth 20 Mbit/s.
set -eu
dev=${1:-eth0}
sudo tc qdisc replace dev "$dev" root handle 1: netem delay 90ms 40ms distribution normal loss 8% reorder 3% 50%
sudo tc qdisc replace dev "$dev" parent 1:1 handle 10: tbf rate 20mbit burst 32kbit latency 400ms
