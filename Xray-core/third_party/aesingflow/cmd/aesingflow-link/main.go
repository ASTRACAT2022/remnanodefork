// aesingflow-link creates a portable aesingflow:// client profile link.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
	"github.com/ASTRACAT2022/aesingflow/pkg/link"
)

func main() {
	server := flag.String("server", "", "AesingFlow server host:port")
	token := flag.String("token", "", "AesingFlow access token")
	serverName := flag.String("server-name", "", "optional TLS certificate name")
	name := flag.String("name", "", "optional profile name")
	cc := flag.String("cc", "brutal", "QUIC congestion controller: brutal (default) or cubic")
	brutalBPS := flag.Uint64("brutal-bps", aesingflow.DefaultBrutalSendRate, "Brutal outbound rate limit in bits/s")
	maxStreams := flag.Int("max-streams", 0, "optional maximum concurrent TCP streams")
	flag.Parse()
	if *server == "" || *token == "" || (*cc != "brutal" && *cc != "cubic") {
		fmt.Fprintln(os.Stderr, "-server and -token are required; -cc must be brutal or cubic")
		os.Exit(2)
	}
	p := link.Profile{Server: *server, Token: *token, ServerName: *serverName, Name: *name, MaxStreams: *maxStreams, DisableBrutal: *cc == "cubic"}
	if !p.DisableBrutal {
		p.BrutalSendRate = *brutalBPS
	}
	uri, err := p.URI()
	if err != nil {
		slog.Error("create AesingFlow link", "error", err)
		os.Exit(1)
	}
	fmt.Println(uri)
}
