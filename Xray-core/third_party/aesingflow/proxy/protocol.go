// Package proxy implements a small TCP proxy carried by AesingFlow streams.
package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	requestMagic  = "AFPR"
	responseMagic = "AFPS"
	protocolVer   = 1

	commandConnect = 1
	statusOK       = 0
	statusFailure  = 1

	addressIPv4   = 1
	addressDomain = 3
	addressIPv6   = 4
)

// Target is the TCP endpoint requested through the tunnel.
type Target struct {
	Host string
	Port uint16
}

func (t Target) Address() string { return net.JoinHostPort(t.Host, fmt.Sprintf("%d", t.Port)) }

func writeRequest(w io.Writer, target Target) error {
	host := []byte(target.Host)
	if len(host) == 0 || len(host) > 255 {
		return fmt.Errorf("proxy: host length must be between 1 and 255 bytes")
	}
	addressType := byte(addressDomain)
	if ip := net.ParseIP(target.Host); ip != nil {
		if ip.To4() != nil {
			addressType, host = addressIPv4, ip.To4()
		} else {
			addressType, host = addressIPv6, ip.To16()
		}
	}
	header := []byte{requestMagic[0], requestMagic[1], requestMagic[2], requestMagic[3], protocolVer, commandConnect, addressType}
	if _, err := w.Write(header); err != nil {
		return err
	}
	if addressType == addressDomain {
		if _, err := w.Write([]byte{byte(len(host))}); err != nil {
			return err
		}
	}
	if _, err := w.Write(host); err != nil {
		return err
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], target.Port)
	_, err := w.Write(port[:])
	return err
}

func readRequest(r io.Reader) (Target, error) {
	var header [7]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Target{}, err
	}
	if string(header[:4]) != requestMagic || header[4] != protocolVer || header[5] != commandConnect {
		return Target{}, fmt.Errorf("proxy: invalid request header")
	}
	var host []byte
	switch header[6] {
	case addressIPv4:
		host = make([]byte, net.IPv4len)
	case addressIPv6:
		host = make([]byte, net.IPv6len)
	case addressDomain:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return Target{}, err
		}
		if length[0] == 0 {
			return Target{}, fmt.Errorf("proxy: empty target host")
		}
		host = make([]byte, length[0])
	default:
		return Target{}, fmt.Errorf("proxy: unsupported target address type")
	}
	if _, err := io.ReadFull(r, host); err != nil {
		return Target{}, err
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return Target{}, err
	}
	if header[6] == addressIPv4 || header[6] == addressIPv6 {
		host = []byte(net.IP(host).String())
	}
	return Target{Host: string(host), Port: binary.BigEndian.Uint16(port[:])}, nil
}

func writeResponse(w io.Writer, status byte) error {
	_, err := w.Write([]byte{responseMagic[0], responseMagic[1], responseMagic[2], responseMagic[3], protocolVer, status})
	return err
}

func readResponse(r io.Reader) error {
	var response [6]byte
	if _, err := io.ReadFull(r, response[:]); err != nil {
		return err
	}
	if string(response[:4]) != responseMagic || response[4] != protocolVer {
		return fmt.Errorf("proxy: invalid server response")
	}
	if response[5] != statusOK {
		return fmt.Errorf("proxy: server could not connect to target")
	}
	return nil
}
