package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	
	"github.com/yinghuocho/golibfq/mux"
	"github.com/yinghuocho/golibfq/sockstun"
	"github.com/yinghuocho/golibfq/transport/httptran"
	"github.com/yinghuocho/golibfq/utils"
	"github.com/yinghuocho/gosocks"
)

type serverOptions struct {
	logFilename    string
	pidFilename    string
	httpAddr       string
	httpsAddr      string
	certFile       string
	keyFile        string
	localSocksAddr string
}

type tunnelConnHandler struct {
	socksAddr    string
	socksTimeout time.Duration
	socksAuth    sockstun.TunnelAuthenticator
}

func (h *tunnelConnHandler) serveWithMux(conn net.Conn) {
	server := mux.NewServer(conn)
	for {
		stream, err := server.Accept()
		if err != nil {
			log.Printf("error to accept new mux streams: %s", err)
			server.Close()
			return
		}
		go func(cc net.Conn) {
			s, err := net.DialTimeout("tcp", h.socksAddr, h.socksTimeout)
			if err != nil {
				log.Printf("error connecting SOCKS server: %s", err)
				cc.Close()
				return
			}
			socks := &gosocks.SocksConn{s.(net.Conn), h.socksTimeout}
			if h.socksAuth.ServerAuthenticate(cc, socks) != nil {
				cc.Close()
				socks.Close()
				return
			}
			sockstun.TunnelServer(cc, socks)
		}(stream)
	}
}

func (h *tunnelConnHandler) serveWithoutMux(conn net.Conn) {
	s, err := net.DialTimeout("tcp", h.socksAddr, h.socksTimeout)
	if err != nil {
		log.Printf("error connecting SOCKS server: %s", err)
		conn.Close()
		return
	}
	socks := &gosocks.SocksConn{s.(net.Conn), h.socksTimeout}
	if h.socksAuth.ServerAuthenticate(conn, socks) != nil {
		conn.Close()
		socks.Close()
		return
	}
	sockstun.TunnelServer(conn, socks)
}

func main() {
	var opts serverOptions

	flag.StringVar(&opts.httpAddr, "http-addr", ":80", "http server address")
	flag.StringVar(&opts.httpsAddr, "https-addr", "", "https server address")
	flag.StringVar(&opts.certFile, "cert-file", "", "https certificate")
	flag.StringVar(&opts.keyFile, "key-file", "", "https key file")
	flag.StringVar(&opts.localSocksAddr, "local-socks-addr", "127.0.0.1:10800", "SOCKS server address")
	flag.StringVar(&opts.logFilename, "logfile", "", "file to record log")
	flag.StringVar(&opts.pidFilename, "pidfile", "", "file to save process id")
	flag.Parse()

	// initiate log file
	logFile := utils.RotateLog(opts.logFilename, nil)
	if opts.logFilename != "" && logFile == nil {
		log.Printf("WARNING: fail to initiate log file")
	}

	// a channel to receive quit signal from server daemons
	quit := make(chan bool)

	// start SOCKS server
	socksListener, err := net.Listen("tcp", opts.localSocksAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on SOCKS address %s: %s", opts.localSocksAddr, err)
	}
	socksServer := gosocks.NewBasicServer(opts.localSocksAddr, 5*time.Minute)
	go func() {
		err := socksServer.Serve(socksListener)
		if err != nil {
			log.Printf("FATAL: error to serve SOCKS: %s", err)
		}
		close(quit)
	}()
	log.Printf("SOCKS server listens on %s", opts.localSocksAddr)

	// start tunnel server
	httpListener, err := net.Listen("tcp", opts.httpAddr)
	if err != nil {
		log.Fatalf("FATAL: fail to listen on HTTP address %s: %s", opts.httpAddr, err)
	}
	connHandler := &tunnelConnHandler{
		socksAddr:    opts.localSocksAddr,
		socksTimeout: socksServer.GetTimeout(),
		socksAuth:    sockstun.NewTunnelAnonymousAuthenticator(),
	}

	tunnelHandler := httptran.NewPollServerHandler(connHandler.serveWithMux)
	tunnelHandler.Run()
	httpServer := &http.Server{
		Addr:         opts.httpAddr,
		Handler:      tunnelHandler,
		ReadTimeout:  10 * time.Minute,
		WriteTimeout: 10 * time.Minute,
	}
	go httpServer.Serve(httpListener)
	log.Printf("HTTP server listens on %s", opts.httpAddr)

	if opts.httpsAddr != "" && opts.certFile != "" && opts.keyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.certFile, opts.keyFile)
		if err != nil {
			log.Fatalf("FATAL: fail to load X509 keypair: %s", err)
		}
		httpsListener, err := tls.Listen("tcp", opts.httpsAddr, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
		if err != nil {
			log.Fatalf("FATAL: fail to listen on HTTPS address %s: %s", opts.httpsAddr, err)
		}
		httpsServer := &http.Server{
			Addr:         opts.httpsAddr,
			Handler:      tunnelHandler,
			ReadTimeout:  10 * time.Minute,
			WriteTimeout: 10 * time.Minute,
		}
		go httpsServer.Serve(httpsListener)
		log.Printf("HTTPS server listens on %s", opts.httpsAddr)
		defer httpsListener.Close()
	}

	// pidfile and clean up
	utils.SavePid(opts.pidFilename)
	defer socksListener.Close()
	defer httpListener.Close()

	// wait for control/quit signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
loop:
	for {
		select {
		case <-quit:
			log.Printf("quit signal received")
			break loop
		case s := <-c:
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				break loop
			case syscall.SIGHUP:
				logFile = utils.RotateLog(opts.logFilename, logFile)
			}
		}
	}
	log.Printf("done")
}
