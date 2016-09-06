package main

import (
	"bufio"
	"bytes"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yinghuocho/tarfs"
	"github.com/yinghuocho/golibfq/transport/httptran"
)

var (
	meekTR *http.Transport = &http.Transport{
		Proxy: nil,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Minute,
		}).Dial,
		TLSHandshakeTimeout: 30 * time.Second,
	}
)

func (t *tunnelHandler) loadTunnelPeers(fs *tarfs.FileSystem) error {
	var peers []tunnelPeer
	data, err := fs.Get("meektunnels.txt")
	if err != nil {
		log.Printf("fail to load embedded meek tunnels (resources/meektunnels.txt): %s", err)
		return err
	}
	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	for scanner.Scan() {
		s := strings.Trim(scanner.Text(), " \r\n ")
		if !strings.HasPrefix(s, "#") {
			pair := strings.Split(s, ",")
			if len(pair) != 2 {
				continue
			}
			u, e := url.Parse(pair[0])
			if e != nil {
				continue
			}
			peers = append(
				peers,
				&meekPeer{
					gen: &httptran.DomainFrontingPollRequestGenerator{
						URL:  u,
						Host: pair[1],
					},
				})
		}
	}
	if peers == nil {
		return errors.New("found no valid meek tunnel")
	}
	t.peers = peers
	return nil
}

type meekPeer struct {
	gen *httptran.DomainFrontingPollRequestGenerator
}

func (m *meekPeer) connect(timeout time.Duration) net.Conn {
	conn, err := httptran.NewPollClientSession(meekTR, m.gen)
	if err != nil {
		return nil
	} else {
		return conn
	}
}

func (m *meekPeer) serialize() string {
	return strings.Join([]string{m.gen.URL.String(), m.gen.Host}, ",")
}
