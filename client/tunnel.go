package main

import (
	"crypto/x509"
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
	state   *fireflyState
	caCerts *x509.CertPool
	appData *utils.AppData

	quit chan bool
	ch   chan *tunnelRequest
	auth sockstun.TunnelAuthenticator

	peerGroups map[string][]tunnelPeer
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

func (t *tunnelHandler) sortPeers() []tunnelPeer {
	state := make(map[string]int)
	v, ok := t.appData.Get("tunnelPeerState")
	if ok {
		json.Unmarshal([]byte(v), &state)
	}
	// sort by state
	by := func(p1, p2 tunnelPeer) bool {
		return state[p1.serialize()] < state[p2.serialize()]
	}

	var groups [][]tunnelPeer
	cnt := 0
	for _, peers := range t.peerGroups {
		// shuffle
		cnt += len(peers)
		for i := range peers {
			j := rand.Intn(i + 1)
			peers[i], peers[j] = peers[j], peers[i]
		}
		// remove shuffle? because the sort is non-stable anyway
		sort.Sort(sort.Reverse(&peerSorter{peers: peers, by: by}))
		groups = append(groups, peers)
	}
	all := make([]tunnelPeer, cnt)
	i := 0
	j := 0
	cur := 0
	for {
		if j < len(groups[i]) {
			all[cur] = groups[i][j]
			cur += 1
			if cur == cnt {
				break
			}
		}
		i += 1
		if i >= len(groups) {
			i = 0
			j += 1
		}
	}
	return all
}

func (t *tunnelHandler) muxClient() *mux.Client {
	start := time.Now()
	conn, succ, failed := t.dialParallel(10 * time.Minute)
	ms := int(time.Now().Sub(start).Nanoseconds() / 1000000)
	t.savePeerState(succ, failed)
	if conn == nil {
		t.state.event("client", "connect-timeout", "", 0)
		log.Printf("connect attempt timed out")
		return nil
	}
	p := succ.serialize()
	log.Printf("connected to peer: %s|%v", p, ms)
	t.state.event("client", "connect-succ", p, ms)
	return mux.NewClient(conn)
}

type tunnelDailRet struct {
	c net.Conn
	p tunnelPeer
}

func (t *tunnelHandler) dialParallel(timeout time.Duration) (net.Conn, tunnelPeer, []tunnelPeer) {
	ret := make(chan *tunnelDailRet)
	quit := make(chan bool)

	// rand by historical connectivity
	all := t.sortPeers()
	// give enough buffer so token channel would not be blocked
	// initiate five attemps
	waiting := len(all)
	token := make(chan bool, waiting)
	for i := 0; i < 5; i++ {
		token <- true
		waiting -= 1
		if waiting == 0 {
			break
		}
	}
	for _, peer := range all {
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
				log.Printf("failed to connect peer: %s", r.p.serialize())
				failedPeers = append(failedPeers, r.p)
				// one fail, fire another if someone waiting
				if waiting > 0 {
					token <- true
					waiting -= 1
				}
				if failedCnt == len(all) {
					log.Printf("all attemps to connect tunnel address have failed")
				} else {
					continue
				}
			}
			close(quit)
			return r.c, r.p, failedPeers
		case <-time.After(200 * time.Millisecond):
			// every 200 ms, fire a waiting one
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
loop:
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
			break loop
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
