// aesingflow-bench is a small repeatable stream/datagram throughput probe, not a benchmark replacement.
package main

import "fmt"

func main() {
	fmt.Println("Use: go test -bench=. ./... for reproducible library benchmarks. This CLI is reserved for network probes.")
}
