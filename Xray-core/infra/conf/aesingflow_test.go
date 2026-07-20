package conf_test

import (
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/aesingflow"
)

func TestAesingFlowOutboundConfig(t *testing.T) {
	creator := func() Buildable {
		return new(AesingFlowClientConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"server": "de1.node.example",
				"serverPort": 4433,
				"token": "test-token",
				"tls": {"serverName": "de1.node.example", "caFile": "/etc/ssl/aesingflow-ca.pem"},
				"maxStreams": 256,
				"brutalBps": 250000000
			}`,
			Parser: loadJSON(creator),
			Output: &aesingflow.Config{
				Server:     "de1.node.example",
				ServerPort: 4433,
				Token:      "test-token",
				ServerName: "de1.node.example",
				CaFile:     "/etc/ssl/aesingflow-ca.pem",
				MaxStreams: 256,
				BrutalBps:  250000000,
			},
		},
	})
}
