package main

import (
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/skratchdot/open-golang/open"

	"github.com/yinghuocho/i18n"
)

var (
	templateFuncMap = template.FuncMap{
		"i18n":      i18n.T,
		"unescaped": func(x string) template.HTML { return template.HTML(x) },
	}
	locales = map[string]string{
		"en_US": "English",
		"zh_CN": "中文(简体)",
	}
)

type fireflyUI struct {
	token       string
	mux         *http.ServeMux
	root        string
	settingsUrl string
	client      *fireflyClient
}

type uiCmd struct {
	cmd  string
	args interface{}
	ret  chan interface{}
}

func token() string {
	rand.Seed(time.Now().UTC().UnixNano())
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 32)
	for i := 0; i < 32; i++ {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func startUI(c *fireflyClient, l net.Listener) *fireflyUI {
	token := token()
	ui := &fireflyUI{
		token:       token,
		root:        fmt.Sprintf("http://%s/%s/", l.Addr().String(), token),
		settingsUrl: fmt.Sprintf("http://%s/%s/settings", l.Addr().String(), token),
		mux:         http.NewServeMux(),
		client:      c,
	}
	ui.mux.Handle(fmt.Sprintf("/%s/settings", ui.token), http.HandlerFunc(ui.settings))
	ui.mux.Handle(fmt.Sprintf("/%s/domains", ui.token), http.HandlerFunc(ui.domains))
	ui.mux.Handle(fmt.Sprintf("/%s/static/", ui.token), http.StripPrefix(fmt.Sprintf("/%s/static/", ui.token), http.FileServer(c.fs)))
	go func() {
		server := &http.Server{
			Handler: ui.mux,
		}
		err := server.Serve(l)
		if err != nil {
			log.Fatalf("FATAL: UI stopped")
		}
		ui.client.exit(err)
	}()
	return ui
}

func (u *fireflyUI) handle(path string, handler http.Handler) string {
	u.mux.Handle(fmt.Sprintf("/%s/%s", u.token, path), handler)
	return u.root + path
}

func (u *fireflyUI) show() {
	open.Start(u.settingsUrl)
}

func (u *fireflyUI) open(url string) {
	open.Start(url)
}

func (u *fireflyUI) domains(w http.ResponseWriter, req *http.Request) {
	data, err := u.client.loadEmbeddedTunnellingDomains()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		w.Write(data)
	}
}

func (u *fireflyUI) settings(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		u.settingsGET(w, req)
	} else if req.Method == "POST" {
		u.settingsPOST(w, req)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

type fireflySettings struct {
	Root                    string
	Version                 string
	HTTPProxyAddr           string
	SocksProxyAddr          string
	LandingPage             string
	CustomTunnellingDomains string
	TunnellingAll           bool
	OpenSettingsPage        bool
	OpenLandingPage         bool
	SetPAC                  bool
	StopAutoUpdate          bool
	Locales                 map[string]string
	CurrentLocale           string
}

func (u *fireflyUI) settingsGET(w http.ResponseWriter, req *http.Request) {
	s, err := u.client.fs.Get("ui.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t, err := template.New("settings").Funcs(templateFuncMap).Parse(string(s))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	settings := &fireflySettings{
		Root:                    u.root,
		Version:                 u.client.uiVersion(),
		HTTPProxyAddr:           u.client.uiHTTPAddr(),
		SocksProxyAddr:          u.client.uiSocksAddr(),
		LandingPage:             u.client.uiLandingPage(),
		TunnellingAll:           u.client.uiTunnellingAll(),
		OpenSettingsPage:        u.client.uiOpenSettingsPage(),
		OpenLandingPage:         u.client.uiOpenLandingPage(),
		SetPAC:                  u.client.uiSetPAC(),
		StopAutoUpdate:          u.client.uiStopAutoUpdate(),
		CustomTunnellingDomains: u.client.uiCustomTunnellingDomains(),
		Locales:                 locales,
		CurrentLocale:           u.client.uiCurrentLocale(),
	}
	err = t.Execute(w, settings)
	if err != nil {
		log.Printf("template execute error: %s", err)
	}
}

func (u *fireflyUI) settingsPOST(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	id := req.FormValue("id")
	state := req.FormValue("state")
	switch id {
	case "tunnellingAll":
		if state == "1" {
			u.client.uiCommand(&uiCmd{cmd: "tunnellingAllOn"})
		} else {
			u.client.uiCommand(&uiCmd{cmd: "tunnellingAllOff"})
		}
	case "openSettingsPage":
		if state == "1" {
			u.client.uiCommand(&uiCmd{cmd: "openSettingsPageOn"})
		} else {
			u.client.uiCommand(&uiCmd{cmd: "openSettingsPageOff"})
		}
	case "openLandingPage":
		if state == "1" {
			u.client.uiCommand(&uiCmd{cmd: "openLandingPageOn"})
		} else {
			u.client.uiCommand(&uiCmd{cmd: "openLandingPageOff"})
		}
	case "stopAutoUpdate":
		if state == "1" {
			u.client.uiCommand(&uiCmd{cmd: "stopAutoUpdateOn"})
		} else {
			u.client.uiCommand(&uiCmd{cmd: "stopAutoUpdateOff"})
		}
	case "setPAC":
		if state == "1" {
			u.client.uiCommand(&uiCmd{cmd: "setPACOn"})
		} else {
			u.client.uiCommand(&uiCmd{cmd: "setPACOff"})
		}
	case "updateCustomTunnellingDomains":
		args := []string{}
		raw := strings.Split(state, "\n")
		for _, v := range raw {
			u, e := url.Parse(v)
			if e == nil {
				switch {
				case u.Host != "":
					args = append(args, u.Host)
				case u.Path != "":
					args = append(args, u.Path)
				}
			}
		}
		u.client.uiCommand(&uiCmd{cmd: "updateCustomTunnellingDomains", args: args})

	case "locale":
		u.client.uiCommand(&uiCmd{cmd: strings.Join([]string{"changeLocale", state}, "|")})
	default:
		http.Error(w, "Unexpected settings option", http.StatusBadRequest)
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
}

func (c *fireflyClient) uiCommand(cmd *uiCmd) {
	c.uiCh <- cmd
}

func (c *fireflyClient) uiVersion() string {
	cmd := &uiCmd{cmd: "version", ret: make(chan interface{})}
	c.uiCh <- cmd
	v := <-cmd.ret
	return v.(string)
}

func (c *fireflyClient) uiSetPAC() bool {
	cmd := &uiCmd{cmd: "setPAC?", ret: make(chan interface{})}
	c.uiCh <- cmd
	v := <-cmd.ret
	return v.(bool)
}

func (c *fireflyClient) uiTunnellingAll() bool {
	cmd := &uiCmd{cmd: "tunnellingAll?", ret: make(chan interface{})}
	c.uiCh <- cmd
	v := <-cmd.ret
	return v.(bool)
}

func (c *fireflyClient) uiHTTPAddr() string {
	cmd := &uiCmd{cmd: "httpAddr", ret: make(chan interface{})}
	c.uiCh <- cmd
	v := <-cmd.ret
	return v.(string)
}

func (c *fireflyClient) uiSocksAddr() string {
	cmd := &uiCmd{cmd: "socksAddr", ret: make(chan interface{})}
	c.uiCh <- cmd
	v := <-cmd.ret
	return v.(string)
}

func (c *fireflyClient) uiLandingPage() string {
	cmd := &uiCmd{cmd: "landingPage", ret: make(chan interface{})}
	c.uiCh <- cmd
	v := <-cmd.ret
	return v.(string)
}

func (c *fireflyClient) uiCurrentLocale() string {
	cmd := &uiCmd{cmd: "currentLocale", ret: make(chan interface{})}
	c.uiCh <- cmd
	v := <-cmd.ret
	return v.(string)
}

func (c *fireflyClient) uiOpenSettingsPage() bool {
	cmd := &uiCmd{cmd: "openSettingsPage?", ret: make(chan interface{})}
	c.uiCh <- cmd
	v := <-cmd.ret
	return v.(bool)
}

func (c *fireflyClient) uiOpenLandingPage() bool {
	cmd := &uiCmd{cmd: "openLandingPage?", ret: make(chan interface{})}
	c.uiCh <- cmd
	v := <-cmd.ret
	return v.(bool)
}

func (c *fireflyClient) uiStopAutoUpdate() bool {
	cmd := &uiCmd{cmd: "stopAutoUpdate?", ret: make(chan interface{})}
	c.uiCh <- cmd
	v := <-cmd.ret
	return v.(bool)
}

func (c *fireflyClient) uiCustomTunnellingDomains() string {
	cmd := &uiCmd{cmd: "customTunnellingDomains", ret: make(chan interface{})}
	c.uiCh <- cmd
	v := <-cmd.ret
	return v.(string)
}

// use channel to avoid races
func (c *fireflyClient) uiCommandProc() {
	for {
		cmd := <-c.uiCh
		switch {
		case cmd.cmd == "openSettingsPageOn":
			c.switchFlags("openSettingsPage", true)
		case cmd.cmd == "openSettingsPageOff":
			c.switchFlags("openSettingsPage", false)
		case cmd.cmd == "openLandingPageOn":
			c.switchFlags("openLandingPage", true)
		case cmd.cmd == "openLandingPageOff":
			c.switchFlags("openLandingPage", false)
		case cmd.cmd == "setPACOn":
			c.switchFlags("setPAC", true)
		case cmd.cmd == "setPACOff":
			c.switchFlags("setPAC", false)
		case cmd.cmd == "tunnellingAllOn":
			c.switchTunnelling(true)
		case cmd.cmd == "tunnellingAllOff":
			c.switchTunnelling(false)
		case cmd.cmd == "stopAutoUpdateOn":
			c.switchFlags("stopAutoUpdate", true)
			c.stopUpdater()
		case cmd.cmd == "stopAutoUpdateOff":
			c.switchFlags("stopAutoUpdate", false)
			c.startUpdater()
		case strings.HasPrefix(cmd.cmd, "changeLocale|"):
			lang := strings.Split(cmd.cmd, "|")[1]
			c.changeLocale(lang)
		case cmd.cmd == "version":
			cmd.ret <- c.version()
		case cmd.cmd == "httpAddr":
			cmd.ret <- c.httpListener.Addr().String()
		case cmd.cmd == "socksAddr":
			cmd.ret <- c.socksListener.Addr().String()
		case cmd.cmd == "landingPage":
			cmd.ret <- c.options.landingPage
		case cmd.cmd == "tunnellingAll?":
			cmd.ret <- c.socksHandler.tunnellingAll
		case cmd.cmd == "openSettingsPage?":
			cmd.ret <- c.openSettingsPage()
		case cmd.cmd == "openLandingPage?":
			cmd.ret <- c.openLandingPage()
		case cmd.cmd == "setPAC?":
			cmd.ret <- c.setPAC()
		case cmd.cmd == "stopAutoUpdate?":
			cmd.ret <- c.stopAutoUpdate()
		case cmd.cmd == "currentLocale":
			cmd.ret <- i18n.CurrentLocale()
		case cmd.cmd == "customTunnellingDomains":
			cmd.ret <- strings.Join(c.customTunnellingDomains(), "\n")
		case cmd.cmd == "updateCustomTunnellingDomains":
			c.updateCustomTunnellingDomains(cmd.args.([]string))

		default:
			log.Printf("unknown command from UI")
		}
	}
}
