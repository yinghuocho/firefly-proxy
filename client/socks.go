package main

import (
	"log"
	"path"
	"strings"
	"time"

	"github.com/yinghuocho/golibfq/chain"
	"github.com/yinghuocho/gosocks"
)

type relayHandler struct {
	basic                     *gosocks.BasicSocksHandler
	nextHop                   string
	embeddedTunnellingDomains map[string]bool
	customTunnellingDomains   []string
	tunnellingAll             bool
}

func (r *relayHandler) lookup(dst string, conn *gosocks.SocksConn) chain.SocksChain {
	chain := &chain.SocksSocksChain{
		SocksDialer: &gosocks.SocksDialer{
			Timeout: conn.Timeout,
			Auth:    &gosocks.AnonymousClientAuthenticator{},
		},
		SocksAddr: r.nextHop,
	}

	if r.tunnellingAll {
		return chain
	}

	labels := strings.Split(dst, ".")
	for i := 0; i < len(labels); i++ {
		_, ok := r.embeddedTunnellingDomains[strings.Join(labels[i:], ".")]
		if ok {
			return chain
		}
	}

	for _, v := range r.customTunnellingDomains {
		matched, _ := path.Match(v, dst)
		if matched {
			return chain
		}
	}

	return nil
}

func (r *relayHandler) handleUDPAssociate(req *gosocks.SocksRequest, conn *gosocks.SocksConn) {
	clientBind, clientAssociate, udpReq, clientAddr, err := r.basic.UDPAssociateFirstPacket(req, conn)
	if err != nil {
		conn.Close()
		return
	}
	chain := r.lookup(udpReq.DstHost, conn)
	if chain != nil {
		chain.UDPAssociate(req, conn, clientBind, clientAssociate, udpReq, clientAddr)
	} else {
		r.basic.UDPAssociateForwarding(conn, clientBind, clientAssociate, udpReq, clientAddr)
	}
}

func (r *relayHandler) ServeSocks(conn *gosocks.SocksConn) {
	conn.SetReadDeadline(time.Now().Add(conn.Timeout))
	req, err := gosocks.ReadSocksRequest(conn)
	if err != nil {
		log.Printf("error in ReadSocksRequest: %s", err)
		return
	}

	switch req.Cmd {
	case gosocks.SocksCmdConnect:
		chain := r.lookup(req.DstHost, conn)
		if chain != nil {
			chain.TCP(req, conn)
		} else {
			r.basic.HandleCmdConnect(req, conn)
		}
		return
	case gosocks.SocksCmdUDPAssociate:
		r.handleUDPAssociate(req, conn)
		return
	case gosocks.SocksCmdBind:
		conn.Close()
		return
	default:
		return
	}
}

func (r *relayHandler) Quit() {}
