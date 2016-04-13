package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/getlantern/systray"

	"github.com/yinghuocho/golibfq/chain"
	"github.com/yinghuocho/golibfq/sockstun"
	"github.com/yinghuocho/golibfq/utils"
	"github.com/yinghuocho/gosocks"
	"github.com/yinghuocho/i18n"
	"github.com/yinghuocho/tarfs"
)

const (
	FIREFLY_VERSION = "0.4.0"
)

type clientOptions struct {
	logFilename       string
	pidFilename       string
	tunnellingAll     bool
	blockedDomainFile string
	landingPage       string
	updatePubKey      string
	updateCaCerts     string
	updateURL         string
	localSocksAddr    string
	localHTTPAddr     string
	localUIAddr       string
	trackingID        string
}

type fireflyClient struct {
	options clientOptions
	appData *utils.AppData
	fs      *tarfs.FileSystem
	logFile *os.File

	tunnelListener net.Listener
	tunnelProxy    *gosocks.Server
	httpListener   net.Listener
	httpProxy      *goproxy.ProxyHttpServer
	socksListener  net.Listener
	socksHandler   *relayHandler
	socksProxy     *gosocks.Server

	updater *fireflyUpdater
	state   *fireflyState

	systrayItems fireflyMenu
	ui           *fireflyUI

	uiCh        chan string
	exitCh      chan error
	chExitFuncs chan func()
}

type fireflyMenu struct {
	settings *systray.MenuItem
	quit     *systray.MenuItem
}

func genUUID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func (c *fireflyClient) loadEmbeddedBlockedDomains() ([]byte, error) {
	data, err := c.fs.Get("domains.txt")
	if err != nil {
		log.Printf("fail to load embedded domains: %s", err)
		return nil, err
	}
	return data, nil
}

func (c *fireflyClient) loadBlockedDomains() map[string]bool {
	var scanner *bufio.Scanner
	ret := make(map[string]bool)
	path := c.options.blockedDomainFile
	if path != "" {
		file, err := os.Open(c.options.blockedDomainFile)
		if err != nil {
			log.Printf("fail to load tunneling domains from %s: %s", path, err)
			return nil
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		data, err := c.loadEmbeddedBlockedDomains()
		if err != nil {
			return nil
		}
		scanner = bufio.NewScanner(bytes.NewBuffer(data))
	}

	for scanner.Scan() {
		s := strings.Trim(scanner.Text(), " \r\n ")
		if !strings.HasPrefix(s, "#") {
			ret[s] = true
		}
	}
	return ret
}

func (c *fireflyClient) loadUpdateKey() (*rsa.PublicKey, error) {
	path := c.options.updatePubKey
	var data []byte
	var e error
	if path != "" {
		data, e = ioutil.ReadFile(path)
	} else {
		data, e = c.fs.Get("keys/updatepub.pem")

	}
	if e != nil {
		return nil, e
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("couldn't decode PEM file")
	}
	pubkey, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	return pubkey.(*rsa.PublicKey), nil
}

func (c *fireflyClient) loadUpdateCaCerts() *x509.CertPool {
	var certs []byte
	var err error
	path := c.options.updateCaCerts
	if path != "" {
		certs, err = ioutil.ReadFile(path)
	} else {
		certs, err = c.fs.Get("keys/updateca.pem")
	}
	if err != nil {
		return nil
	}
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certs)
	return certPool
}

func (c *fireflyClient) version() string {
	return fmt.Sprintf("Firefly-%s %s", runtime.GOOS, FIREFLY_VERSION)
}

func (c *fireflyClient) uuid() string {
	if c.appData != nil {
		id, ok := c.appData.Get("uuid")
		if ok {
			return id
		} else {
			id, err := genUUID()
			if err != nil {
				return "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
			} else {
				c.appData.Put("uuid", id)
				return id
			}
		}
	} else {
		return "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
	}
}

func (c *fireflyClient) isTunnellingAll(domains map[string]bool) bool {
	if c.options.tunnellingAll {
		return true
	}
	if domains == nil || len(domains) == 0 {
		return true
	}
	if c.appData != nil {
		v, ok := c.appData.Get("tunnellingAll")
		if ok && v == "1" {
			return true
		}
	}
	return false
}

func (c *fireflyClient) openSettingsPage() bool {
	if c.appData != nil {
		v, ok := c.appData.Get("openSettingsPage")
		if ok && v == "0" {
			return false
		}
	}
	return true
}

func (c *fireflyClient) openLandingPage() bool {
	if c.appData != nil {
		v, ok := c.appData.Get("openLandingPage")
		if ok && v == "0" {
			return false
		}
	}
	return true
}

func (c *fireflyClient) stopAutoUpdate() bool {
	if c.appData != nil {
		v, ok := c.appData.Get("stopAutoUpdate")
		if ok && v == "1" {
			return true
		}
	}
	return false
}

func (c *fireflyClient) startUpdater() {
	proxyURL, _ := url.Parse("http://" + c.httpListener.Addr().String())
	privKey, e := c.loadUpdateKey()
	if e == nil {
		caCerts := c.loadUpdateCaCerts()
		c.updater = newUpdater(FIREFLY_VERSION, 2*time.Hour, privKey, caCerts, c.options.updateURL, proxyURL)
		go c.updater.run()
	}
}

func (c *fireflyClient) stopUpdater() {
	if c.updater != nil {
		c.updater.stop()
		c.updater = nil
	}
}

func (c *fireflyClient) switchTunnelling(state bool) {
	newHandler := &relayHandler{
		basic:          c.socksHandler.basic,
		nextHop:        c.socksHandler.nextHop,
		blockedDomains: c.socksHandler.blockedDomains,
		tunnellingAll:  state,
	}
	c.socksHandler = newHandler
	c.socksProxy.ChangeHandler(c.socksHandler)
	if c.appData != nil {
		if state {
			c.appData.Put("tunnellingAll", "1")
		} else {
			c.appData.Put("tunnellingAll", "0")
		}
	}
}

func (c *fireflyClient) switchFlags(name string, state bool) {
	if c.appData != nil {
		if state {
			c.appData.Put(name, "1")
		} else {
			c.appData.Put(name, "0")
		}
	}
}

func (c *fireflyClient) configureI18n() {
	i18n.SetMessagesFunc(func(filename string) ([]byte, error) {
		return c.fs.Get(fmt.Sprintf("locale/%s", filename))
	})
	if c.appData != nil {
		locale, ok := c.appData.Get("locale")
		if ok {
			err := i18n.SetLocale(locale)
			if err == nil {
				return
			}
		}
	}
	if err := i18n.UseOSLocale(); err != nil {
		log.Printf("i18n.UseOSLocale: %q", err)
	}
}

func (c *fireflyClient) reloadSystray() {
	c.systrayItems.settings.SetTitle(i18n.T("TRAY_SETTINGS"))
	c.systrayItems.quit.SetTitle(i18n.T("TRAY_QUIT"))
}

func (c *fireflyClient) configureSystray() {
	icon, err := c.fs.Get("icons/24.ico")
	if err != nil {
		log.Fatalf("Unable to load icon for system tray: %s", err)
	}
	systray.SetIcon(icon)
	systray.SetTooltip("Firefly")
	c.systrayItems = fireflyMenu{
		settings: systray.AddMenuItem(i18n.T("TRAY_SETTINGS"), ""),
		quit:     systray.AddMenuItem(i18n.T("TRAY_QUIT"), ""),
	}
	go func() {
		for {
			select {
			case <-c.systrayItems.settings.ClickedCh:
				c.ui.show()
			case <-c.systrayItems.quit.ClickedCh:
				c.exit(nil)
				return
			}
		}
	}()
}

func (c *fireflyClient) changeLocale(locale string) {
	if c.appData != nil {
		c.appData.Put("locale", locale)
	}
	c.configureI18n()
	c.reloadSystray()
}

func (c *fireflyClient) uiCommand(cmd string) {
	c.uiCh <- cmd
}

func (c *fireflyClient) uiCommandProc() {
	for {
		cmd := <-c.uiCh
		switch {
		case cmd == "openSettingsPageOn":
			c.switchFlags("openSettingsPage", true)
		case cmd == "openSettingsPageOff":
			c.switchFlags("openSettingsPage", false)
		case cmd == "openLandingPageOn":
			c.switchFlags("openLandingPage", true)
		case cmd == "openLandingPageOff":
			c.switchFlags("openLandingPage", false)
		case cmd == "tunnellingAllOn":
			c.switchTunnelling(true)
		case cmd == "tunnellingAllOff":
			c.switchTunnelling(false)
		case cmd == "stopAutoUpdateOn":
			c.switchFlags("stopAutoUpdate", true)
			c.stopUpdater()
		case cmd == "stopAutoUpdateOff":
			c.switchFlags("stopAutoUpdate", false)
			c.startUpdater()
		case strings.HasPrefix(cmd, "changeLocale|"):
			lang := strings.Split(cmd, "|")[1]
			c.changeLocale(lang)
		default:
			log.Printf("unknown command from UI")
		}
	}
}

func (c *fireflyClient) exit(err error) {
	defer func() { c.exitCh <- err }()
	for {
		select {
		case f := <-c.chExitFuncs:
			log.Printf("Calling exit func")
			f()
		default:
			log.Printf("No exit func remaining, exit now")
			return
		}
	}
}

func (c *fireflyClient) addExitFunc(exitFunc func()) {
	c.chExitFuncs <- exitFunc
}

func (c *fireflyClient) waitForExit() error {
	return <-c.exitCh
}

func (c *fireflyClient) handleSignals() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		s := <-ch
		switch s {
		case syscall.SIGHUP:
			utils.RotateLog(c.options.logFilename, c.logFile)
		case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
			log.Printf("Got signal \"%s\", exiting...", s)
			c.exit(nil)
		}
	}()
}

func (c *fireflyClient) _main() {
	flag.StringVar(&c.options.localSocksAddr, "local-socks-addr", "127.0.0.1:38250", "SOCKS proxy address")
	flag.StringVar(&c.options.localHTTPAddr, "local-http-addr", "127.0.0.1:38251", "HTTP proxy address")
	flag.StringVar(&c.options.localUIAddr, "local-ui-addr", "127.0.0.1:38252", "Web UI address, use random local address when specified address is not available")
	flag.StringVar(&c.options.blockedDomainFile, "blocked-domain-file", "", "blocked domains that need to go through tunnel, use embedded domain list if not specified")
	flag.BoolVar(&c.options.tunnellingAll, "tunnelling-all", false, "whether tunnelling all traffic")
	flag.StringVar(&c.options.logFilename, "logfile", "", "file to record log")
	flag.StringVar(&c.options.pidFilename, "pidfile", "", "file to save process id")
	flag.StringVar(&c.options.landingPage, "landing-page", "https://gofirefly.org/page/", "")
	flag.StringVar(&c.options.updatePubKey, "update-pubkey-file", "", "PEM encoded RSA public key file, use embedded public key if not specified")
	flag.StringVar(&c.options.updatePubKey, "update-cacerts", "", "trusted CA certificates for update, use embedded cacerts if not specified")
	flag.StringVar(&c.options.updateURL, "update-url", "https://update.gofirefly.org/update", "url for auto-update")
	flag.StringVar(&c.options.trackingID, "tracking-id", "UA-76209591-1", "Google Analytics tracking ID")
	flag.Parse()

	var err error
	c.fs, err = tarfs.New(Resources, "")
	if err != nil {
		log.Printf("FATAL: fail to load embedded resources: %s", err)
		os.Exit(1)
	}

	c.appData, err = utils.OpenAppData("firefly")
	if err != nil {
		log.Printf("WARNING: unable to load/store customized settings: %s", err)
	}

	// initiate log file
	c.logFile = utils.RotateLog(c.options.logFilename, nil)
	if c.options.logFilename != "" && c.logFile == nil {
		log.Printf("WARNING: fail to initiate log file")
	}

	// listen SOCKS
	localSocksAddr := c.options.localSocksAddr
	c.socksListener, err = net.Listen("tcp", localSocksAddr)
	if err != nil {
		log.Printf("FATAL: fail to listen on SOCKS proxy address %s: %s", localSocksAddr, err)
		os.Exit(1)
	}

	// listen HTTP
	localHTTPAddr := c.options.localHTTPAddr
	c.httpListener, err = net.Listen("tcp", localHTTPAddr)
	if err != nil {
		log.Printf("FATAL: fail to listen on HTTP/S proxy address %s: %s", localHTTPAddr, err)
		os.Exit(1)
	}

	// start tunnel client
	c.tunnelListener, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		log.Printf("FATAL: fail to listen on tunnel client (SOCKS): %s", err)
		os.Exit(1)
	}
	handler := &tunnelHandler{
		appData: c.appData,
		ch:      make(chan *tunnelRequest),
		quit:    make(chan bool),
		auth:    sockstun.NewTunnelAnonymousAuthenticator(),
	}
	err = handler.loadTunnelPeers(c.fs)
	if err != nil {
		log.Printf("FATAL: fail to load tunnel peers")
		os.Exit(1)
	}
	go handler.run()
	c.tunnelProxy = gosocks.NewServer(
		c.tunnelListener.Addr().String(),
		5*time.Minute,
		handler,
		// let handler's authenticator to process SOCKS authentication
		nil,
	)
	go func() {
		err := c.tunnelProxy.Serve(c.tunnelListener)
		if err != nil {
			log.Printf("FATAL: error to serve tunnel client (SOCKS): %s", err)
		}
		c.exit(err)
	}()
	tunnelProxyAddr := c.tunnelListener.Addr().String()
	log.Printf("tunnel proxy (SOCKS) listens on %s", tunnelProxyAddr)

	// start SOCKS proxy
	domains := c.loadBlockedDomains()
	c.socksHandler = &relayHandler{
		basic:          &gosocks.BasicSocksHandler{},
		blockedDomains: domains,
		tunnellingAll:  c.isTunnellingAll(domains),
		nextHop:        tunnelProxyAddr,
	}
	c.socksProxy = gosocks.NewServer(
		localSocksAddr,
		5*time.Minute,
		c.socksHandler,
		&gosocks.AnonymousServerAuthenticator{},
	)
	go func() {
		err := c.socksProxy.Serve(c.socksListener)
		if err != nil {
			log.Printf("FATAL: error to serve SOCKS proxy: %s", err)
		}
		c.exit(err)
	}()
	log.Printf("SOCKS proxy listens on %s", c.options.localSocksAddr)

	// start HTTP proxy
	socksDialer := &gosocks.SocksDialer{
		Timeout: 5 * time.Minute,
		Auth:    &gosocks.AnonymousClientAuthenticator{},
	}
	http2Socks := chain.GoproxySocksChain{
		Chain: chain.HTTPSocksChain{
			SocksDialer: socksDialer,
			SocksAddr:   localSocksAddr,
		},
	}
	c.httpProxy = goproxy.NewProxyHttpServer()
	c.httpProxy.OnRequest().DoFunc(http2Socks.HTTP)
	c.httpProxy.OnRequest().HandleConnectFunc(http2Socks.HTTPS)
	go func() {
		err := http.Serve(c.httpListener, c.httpProxy)
		if err != nil {
			log.Printf("FATAL: error to serve HTTP/S proxy: %s", err)
		}
		c.exit(err)
	}()
	log.Printf("HTTP/S proxy listens on %s", localHTTPAddr)

	// i18n
	c.configureI18n()

	// start web based UI
	uiListener, err := net.Listen("tcp", c.options.localUIAddr)
	if err != nil {
		log.Printf("fail to listen on specified UI (HTTP) address: %s", err)
		log.Printf("try to use random local address")
		uiListener, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			log.Fatalf("FATAL: fail to listen on UI (HTTP) address: %s", err)
		}
	}
	c.ui = startUI(c, uiListener)
	go c.uiCommandProc()

	// set PAC
	icon, err := c.fs.Get("icons/24.ico")
	if err != nil {
		log.Fatalf("Unable to load icon for PAC: %s", err)
	}
	err = promptPrivilegeEscalation(icon)
	if err != nil {
		log.Fatalf("Unable to escalate priviledge for setting PAC: %s", err)
	}
	pacURL := c.ui.handle(pacFilename(), pacHandler(c.httpListener.Addr().String()))
	enablePAC(pacURL)
	c.addExitFunc(disablePAC)

	// systray
	c.addExitFunc(systray.Quit)
	c.configureSystray()

	// clean exit with signals
	go c.handleSignals()

	// pid file
	utils.SavePid(c.options.pidFilename)

	// open starting pages
	if c.openSettingsPage() {
		c.ui.show()
	}
	if c.openLandingPage() {
		if c.openSettingsPage() {
			// wait to avoid launching new browser window
			time.Sleep(3 * time.Second)
		}
		c.ui.open(c.options.landingPage)
	}

	// updater
	if !c.stopAutoUpdate() {
		c.startUpdater()
	}

	// state, report without using proxy
	c.state = newState(c.uuid(), c.options.trackingID, nil)
	go c.state.run()
	c.state.event("client", "launch")

	c.waitForExit()
	os.Exit(0)
}

func main() {
	client := &fireflyClient{
		uiCh:        make(chan string),
		exitCh:      make(chan error, 1),
		chExitFuncs: make(chan func(), 10),
	}
	systray.Run(client._main)
}
