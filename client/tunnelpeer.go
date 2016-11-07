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

type wrappedTransport struct {
        tr *http.Transport
}

func (t *wrappedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
        return t.tr.RoundTrip(req)
}

func (t *wrappedTransport) Close() error {
        t.tr.CloseIdleConnections()
        return nil
}

var (
	meekTR *wrappedTransport = &wrappedTransport{
                tr: &http.Transport{
		        Proxy: nil,
		        Dial: (&net.Dialer{
			        Timeout:   30 * time.Second,
			        KeepAlive: 30 * time.Minute,
		        }).Dial,
		        TLSHandshakeTimeout: 30 * time.Second,
	        },
        }
)

func (t *tunnelHandler) loadTunnelPeers(fs *tarfs.FileSystem) error {
	t.peerGroups = make(map[string][]tunnelPeer)
	data, err := fs.Get("meektunnels.txt")
	if err != nil {
		log.Printf("fail to load embedded meek tunnels (resources/meektunnels.txt): %s", err)
		return err
	}
	scanner := bufio.NewScanner(bytes.NewBuffer(data))
        cnt := 0
	for scanner.Scan() {
		s := strings.Trim(scanner.Text(), " \r\n ")
		if !strings.HasPrefix(s, "#") {
			pair := strings.Split(s, ",")
			if len(pair) != 3 {
				continue
			}
			u, e := url.Parse(pair[0])
			if e != nil {
				continue
			}
                        peers := t.peerGroups[pair[2]]
			t.peerGroups[pair[2]] = append(
				peers,
				&meekPeer{
                                        group: pair[2],
					gen: &httptran.DomainFrontingPollRequestGenerator{
						URL:  u,
						Host: pair[1],
					},
				})
		}
                cnt += 1
	}
	if cnt == 0 {
		return errors.New("found no valid meek tunnel")
	}
	return nil
}

type meekPeer struct {
        group string
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
	return strings.Join([]string{m.gen.URL.String(), m.gen.Host, m.group}, ",")
}
