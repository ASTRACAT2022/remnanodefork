package conf

import (
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/aesingflow"
	"google.golang.org/protobuf/proto"
)

// AesingFlowTLSConfig configures the verified TLS client used for AesingFlow.
// A private CA file must contain public PEM certificates only.
type AesingFlowTLSConfig struct {
	ServerName string `json:"serverName"`
	CAFile     string `json:"caFile"`
}

// AesingFlowClientConfig is the JSON configuration for protocol "aesingflow".
// It transports TCP only and intentionally has no insecure TLS option.
type AesingFlowClientConfig struct {
	Server                        string               `json:"server"`
	ServerPort                    uint32               `json:"serverPort"`
	Token                         string               `json:"token"`
	TLS                           *AesingFlowTLSConfig `json:"tls"`
	MaxStreams                    uint32               `json:"maxStreams"`
	BrutalBps                     uint64               `json:"brutalBps"`
	DisableBrutal                 bool                 `json:"disableBrutal"`
	BrutalDisableLossCompensation bool                 `json:"brutalDisableLossCompensation"`
}

// Build implements Buildable.
func (c *AesingFlowClientConfig) Build() (proto.Message, error) {
	if strings.TrimSpace(c.Server) == "" {
		return nil, errors.New("AesingFlow server is required")
	}
	if c.ServerPort == 0 || c.ServerPort > 65535 {
		return nil, errors.New("AesingFlow serverPort must be between 1 and 65535")
	}
	if strings.TrimSpace(c.Token) == "" {
		return nil, errors.New("AesingFlow token is required")
	}

	config := &aesingflow.Config{
		Server:                        c.Server,
		ServerPort:                    c.ServerPort,
		Token:                         c.Token,
		MaxStreams:                    c.MaxStreams,
		BrutalBps:                     c.BrutalBps,
		DisableBrutal:                 c.DisableBrutal,
		BrutalDisableLossCompensation: c.BrutalDisableLossCompensation,
	}
	if c.TLS != nil {
		config.ServerName = c.TLS.ServerName
		config.CaFile = c.TLS.CAFile
	}
	return config, nil
}
