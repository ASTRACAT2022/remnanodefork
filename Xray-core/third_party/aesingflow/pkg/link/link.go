// Package link parses and creates portable aesingflow:// client links.
package link

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/ASTRACAT2022/aesingflow/pkg/aesingflow"
)

const Scheme = "aesingflow"

// Profile contains portable client connection settings. TLS verification is
// always enabled; private CA files intentionally stay outside a shareable URI.
type Profile struct {
	Server         string
	Token          string
	ServerName     string
	Name           string
	BrutalSendRate uint64
	DisableBrutal  bool
	MaxStreams     int
}

// Parse validates an aesingflow:// link.
//
// Example: aesingflow://token@example.com:4433?sni=example.com
func Parse(raw string) (Profile, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Profile{}, fmt.Errorf("aesingflow link: parse: %w", err)
	}
	if u.Scheme != Scheme {
		return Profile{}, fmt.Errorf("aesingflow link: scheme must be %q", Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return Profile{}, fmt.Errorf("aesingflow link: token is required")
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		return Profile{}, fmt.Errorf("aesingflow link: password component is not supported")
	}
	if u.Hostname() == "" || u.Port() == "" || (u.Path != "" && u.Path != "/") {
		return Profile{}, fmt.Errorf("aesingflow link: server must be host:port")
	}
	if _, err := parsePort(u.Port()); err != nil {
		return Profile{}, err
	}
	p := Profile{Server: u.Host, Token: u.User.Username(), Name: u.Fragment}
	values := u.Query()
	for key, items := range values {
		if len(items) != 1 {
			return Profile{}, fmt.Errorf("aesingflow link: %q may appear only once", key)
		}
		switch key {
		case "sni":
			if items[0] == "" {
				return Profile{}, fmt.Errorf("aesingflow link: sni cannot be empty")
			}
			p.ServerName = items[0]
		case "cc":
			switch items[0] {
			case "", "brutal":
			case "cubic":
				p.DisableBrutal = true
			default:
				return Profile{}, fmt.Errorf("aesingflow link: unsupported cc %q", items[0])
			}
		case "brutal_bps":
			rate, err := strconv.ParseUint(items[0], 10, 64)
			if err != nil || rate == 0 {
				return Profile{}, fmt.Errorf("aesingflow link: brutal_bps must be a positive integer")
			}
			p.BrutalSendRate = rate
		case "max_streams":
			count, err := strconv.Atoi(items[0])
			if err != nil || count <= 0 {
				return Profile{}, fmt.Errorf("aesingflow link: max_streams must be a positive integer")
			}
			p.MaxStreams = count
		default:
			return Profile{}, fmt.Errorf("aesingflow link: unsupported query parameter %q", key)
		}
	}
	if p.DisableBrutal && p.BrutalSendRate != 0 {
		return Profile{}, fmt.Errorf("aesingflow link: brutal_bps cannot be used with cc=cubic")
	}
	return p, nil
}

// URI creates a canonical aesingflow:// link.
func (p Profile) URI() (string, error) {
	if p.Token == "" {
		return "", fmt.Errorf("aesingflow link: token is required")
	}
	host, port, err := net.SplitHostPort(p.Server)
	if err != nil || host == "" {
		return "", fmt.Errorf("aesingflow link: server must be host:port")
	}
	if _, err = parsePort(port); err != nil {
		return "", err
	}
	if p.DisableBrutal && p.BrutalSendRate != 0 {
		return "", fmt.Errorf("aesingflow link: brutal_bps cannot be used with cc=cubic")
	}
	query := url.Values{}
	if p.ServerName != "" {
		query.Set("sni", p.ServerName)
	}
	if p.DisableBrutal {
		query.Set("cc", "cubic")
	} else if p.BrutalSendRate != 0 && p.BrutalSendRate != aesingflow.DefaultBrutalSendRate {
		query.Set("brutal_bps", strconv.FormatUint(p.BrutalSendRate, 10))
	}
	if p.MaxStreams != 0 {
		if p.MaxStreams < 0 {
			return "", fmt.Errorf("aesingflow link: max_streams must be positive")
		}
		query.Set("max_streams", strconv.Itoa(p.MaxStreams))
	}
	return (&url.URL{Scheme: Scheme, User: url.User(p.Token), Host: p.Server, RawQuery: query.Encode(), Fragment: p.Name}).String(), nil
}

// ClientConfig returns an AesingFlow client configuration. tlsConfig must be
// configured by the embedding application; certificate verification is never
// disabled by this package.
func (p Profile) ClientConfig(tlsConfig *tls.Config) aesingflow.ClientConfig {
	if tlsConfig != nil && p.ServerName != "" {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.ServerName = p.ServerName
	}
	return aesingflow.ClientConfig{
		Address:        p.Server,
		TLSConfig:      tlsConfig,
		Token:          p.Token,
		MaxStreams:     p.MaxStreams,
		BrutalSendRate: p.BrutalSendRate,
		DisableBrutal:  p.DisableBrutal,
	}
}

func parsePort(value string) (uint16, error) {
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("aesingflow link: invalid server port %q", value)
	}
	return uint16(port), nil
}
