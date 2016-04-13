package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"net"
	"sort"
	"time"

	"github.com/yinghuocho/golibfq/mux"
	"github.com/yinghuocho/golibfq/sockstun"
	"github.com/yinghuocho/golibfq/utils"
	"github.com/yinghuocho/gosocks"
)

type tunnelRequest struct {
	ret chan net.Conn
}

type tunnelPeer interface {
	connect(time.Duration) net.Conn
	serialize() string
}

type tunnelHandler struct {
	appData *utils.AppData

	quit chan bool
	ch   chan *tunnelRequest
	auth sockstun.TunnelAuthenticator

	peers []tunnelPeer
}

func (t *tunnelHandler) savePeerState(succ tunnelPeer, fail []tunnelPeer) {
	if t.appData == nil {
		return
	} else {
		state := make(map[string]int)
		v, ok := t.appData.Get("tunnelPeerState")
		if ok {
			json.Unmarshal([]byte(v), &state)
		}
		if succ != nil {
			state[succ.serialize()]++
		}
		if fail != nil {
			for _, peer := range fail {
				state[peer.serialize()]--
			}
		}
		b, e := json.Marshal(state)
		if e == nil {
			t.appData.Put("tunnelPeerState", string(b))
		}
	}
}

type peerSorter struct {
	peers []tunnelPeer
	by    func(p1, p2 tunnelPeer) bool // Closure used in the Less method.
}

func (s *peerSorter) Len() int {
	return len(s.peers)
}

func (s *peerSorter) Swap(i, j int) {
	s.peers[i], s.peers[j] = s.peers[j], s.peers[i]
}

// Less is part of sort.Interface. It is implemented by calling the "by" closure in the sorter.
func (s *peerSorter) Less(i, j int) bool {
	return s.by(s.peers[i], s.peers[j])
}

func (t *tunnelHandler) sortPeers() {
	state := make(map[string]int)
	v, ok := t.appData.Get("tunnelPeerState")
	if ok {
		json.Unmarshal([]byte(v), &state)
	}

	// shuffle
	for i := range t.peers {
		j := rand.Intn(i + 1)
		t.peers[i], t.peers[j] = t.peers[j], t.peers[i]
	}

	// sort by state
	by := func(p1, p2 tunnelPeer) bool {
		return state[p1.serialize()] < state[p2.serialize()]
	}
	sort.Reverse(&peerSorter{peers: t.peers, by: by})
}

func (t *tunnelHandler) muxClient() *mux.Client {
	conn, succ, failed := t.dialParallel(30 * time.Minute)
	t.savePeerState(succ, failed)
	if conn == nil {
		return nil
	}
	return mux.NewClient(conn)
}

type tunnelDailRet struct {
	c net.Conn
	p tunnelPeer
}

func (t *tunnelHandler) dialParallel(timeout time.Duration) (net.Conn, tunnelPeer, []tunnelPeer) {
	ret := make(chan *tunnelDailRet)
	quit := make(chan bool)
	// give enough buffer so token channel would not be blocked
	// initiate five attemps
	waiting := len(t.peers)
	token := make(chan bool, waiting)
	for i := 0; i < 5; i++ {
		token <- true
		waiting -= 1
		if waiting == 0 {
			break
		}
	}
	// rand by historical connectivity
	t.sortPeers()
	for _, peer := range t.peers {
		go func(p tunnelPeer) {
			select {
			case <-token:
				c := p.connect(30 * time.Second)
				select {
				case <-quit:
					if c != nil {
						c.Close()
					}
				case ret <- &tunnelDailRet{c: c, p: p}:
				}
			case <-quit:
				return
			}
		}(peer)
	}

	to := time.NewTimer(timeout)
	failedCnt := 0
	var failedPeers []tunnelPeer
	for {
		select {
		case r := <-ret:
			if r.c == nil {
				failedCnt++
				failedPeers = append(failedPeers, r.p)
				// one fail, fire another if someone waiting
				if waiting > 0 {
					token <- true
					waiting -= 1
				}
				if failedCnt == len(t.peers) {
					log.Printf("all attemps to connect tunnel address have failed")
				} else {
					continue
				}
			}
			close(quit)
			return r.c, r.p, failedPeers
		case <-time.After(100 * time.Millisecond):
			// every 100 ms, fire a waiting one
			if waiting > 0 {
				token <- true
				waiting -= 1
			}
		case <-to.C:
			log.Printf("attempt to connect tunnel servers reached overall timeout")
			close(quit)
			return nil, nil, failedPeers
		}
	}
}

func (t *tunnelHandler) muxStream(client *mux.Client) (*mux.Client, *mux.Stream) {
	var err error
	var stream *mux.Stream

	for {
		if client != nil {
			stream, err = client.OpenStream()
			if err != nil {
				client.Close()
				client = nil
				log.Printf("mux Client aborted.")
				continue
			}
			return client, stream
		}
		client = t.muxClient()
		if client == nil {
			return nil, nil
		}
		log.Printf("mux Client established.")
	}
}

func (t *tunnelHandler) run() {
	var client *mux.Client
	var stream *mux.Stream
	for {
		select {
		case request := <-t.ch:
			client, stream = t.muxStream(client)
			if stream == nil {
				close(request.ret)
			} else {
				request.ret <- stream
			}
		case <-t.quit:
			break
		}
	}
}

func (t *tunnelHandler) ServeSocks(conn *gosocks.SocksConn) {
	r := &tunnelRequest{ret: make(chan net.Conn)}
	t.ch <- r
	tunnel, ok := <-r.ret
	if !ok {
		log.Printf("error to get a tunnel connection")
		conn.Close()
		return
	}
	if t.auth.ClientAuthenticate(conn, tunnel) != nil {
		conn.Close()
		tunnel.Close()
		return
	}
	sockstun.TunnelClient(conn, tunnel)
}

func (t *tunnelHandler) Quit() {
	close(t.quit)
}
