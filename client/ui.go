package main

import (
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
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

const (
	settingsTemplate = `
<!DOCTYPE html>
<html>
<head>
<title>{{ i18n "UI_TITLE" }}</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<base href={{ .Root }}>
<script type="text/javascript" src="static/js/jquery-1.12.3.min.js"></script>
</head>
<body>
<p>
<h1>{{ .Version }}</h1>
</p>

<p>
<img src="static/icons/128.ico" alt="Firefly"></img>
</p>

<div id="alert">
</div>

<h2>{{ i18n "UI_LANG" }}</h2>
<ul style="list-style: none;">
<li>
<select id="locale">
{{ range $key, $value := .Locales }}
	<option value="{{ $key }}" {{ if eq $.CurrentLocale $key }} selected {{ end }}>{{ $value }}</option>
{{ end }}
</select>
</li>
</ul>

<h2>{{ i18n "UI_ADDR" }}</h2>
<ul style="list-style: none;">
<li>{{ i18n "UI_HTTPADDR" }}: {{ .HTTPProxyAddr }} </li>
<li>{{ i18n "UI_SOCKSADDR" }}: {{ .SocksProxyAddr }} </li>	
</ul>

<h2>{{ i18n "UI_SETTINGS" }}</h2>
<ul style="list-style: none;">
<li><label><input type="checkbox" id="tunnellingAll" {{ if .TunnellingAll }} checked {{ end }}> {{ i18n "UI_PROXY_ALL" | unescaped }} </label></li>
<li><label><input type="checkbox" id="openSettingsPage" {{ if .OpenSettingsPage }} checked {{ end }}> {{ i18n "UI_SETTINGS_PAGE" }} </label></li>
<li><label><input type="checkbox" id="openLandingPage" {{ if .OpenLandingPage }} checked {{ end }}> {{ i18n "UI_LANDING_PAGE" }}: <a href={{ .LandingPage }} target="_blank">{{ .LandingPage }}</a></label></li>
<li><label><input type="checkbox" id="stopAutoUpdate" {{ if .StopAutoUpdate }} checked {{ end }}> {{ i18n "UI_STOP_AUTOUPDATE" }} </label></li>
</ul>

<h2>{{ i18n "UI_FEEDBACK" }}</h2>
<ul style="list-style: none;">
<li>{{ i18n "UI_CLICK_LINK" }}: <a href="https://github.com/yinghuocho/firefly-proxy/issues" target="_blank">https://github.com/yinghuocho/firefly-proxy/issues</a></label></li>
</ul>

<script>
$(document).ready(function(e) {
	if( /firefox/.test(navigator.userAgent.toLowerCase()) ) {
		$("#alert").append("<h3><strong>{{ i18n "UI_FIREFOXHELP" }}</strong></h3>")
	}
}); 
  	
  	$("input:checkbox").change(function() { 
    	var isChecked = $(this).is(":checked") ? 1:0; 
        $.ajax({
        	url: 'settings',
            type: 'POST',
            data: { id:$(this).attr("id"), state:isChecked }
        });        
    }); 
    
    $('select').on('change', function() {
  		var state = this.value;
  		$.ajax({
        	url: 'settings',
            type: 'POST',
            data: { id:$(this).attr("id"), state:state },
            success: function() {
    			window.location.reload(true);
			},
        });	
	});      
</script>

</body>
</html>
	`
)

type fireflyUI struct {
	token       string
	mux         *http.ServeMux
	root        string
	settingsUrl string
	client      *fireflyClient
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
	if _, err := os.Stat(u.client.options.blockedDomainFile); err == nil {
		http.ServeFile(w, req, u.client.options.blockedDomainFile)
	} else {
		data, err := u.client.loadEmbeddedBlockedDomains()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			w.Write(data)
		}
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
	Root             string
	Version          string
	HTTPProxyAddr    string
	SocksProxyAddr   string
	LandingPage      string
	TunnellingAll    bool
	OpenSettingsPage bool
	OpenLandingPage  bool
	StopAutoUpdate   bool
	Locales          map[string]string
	CurrentLocale    string
}

func (u *fireflyUI) settingsGET(w http.ResponseWriter, req *http.Request) {
	t, err := template.New("settings").Funcs(templateFuncMap).Parse(settingsTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	settings := &fireflySettings{
		Root:             u.root,
		Version:          u.client.version(),
		HTTPProxyAddr:    u.client.httpListener.Addr().String(),
		SocksProxyAddr:   u.client.socksListener.Addr().String(),
		LandingPage:      u.client.options.landingPage,
		TunnellingAll:    u.client.socksHandler.tunnellingAll,
		OpenSettingsPage: u.client.openSettingsPage(),
		OpenLandingPage:  u.client.openLandingPage(),
		StopAutoUpdate:   u.client.stopAutoUpdate(),
		Locales:          locales,
		CurrentLocale:    i18n.CurrentLocale(),
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
			u.client.uiCommand("tunnellingAllOn")
		} else {
			u.client.uiCommand("tunnellingAllOff")
		}
	case "openSettingsPage":
		if state == "1" {
			u.client.uiCommand("openSettingsPageOn")
		} else {
			u.client.uiCommand("openSettingsPageOff")
		}
	case "openLandingPage":
		if state == "1" {
			u.client.uiCommand("openLandingPageOn")
		} else {
			u.client.uiCommand("openLandingPageOff")
		}
	case "stopAutoUpdate":
		if state == "1" {
			u.client.uiCommand("stopAutoUpdateOn")
		} else {
			u.client.uiCommand("stopAutoUpdateOff")
		}

	case "locale":
		u.client.uiCommand(strings.Join([]string{"changeLocale", state}, "|"))
	default:
		http.Error(w, "Unexpected settings option", http.StatusBadRequest)
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
}
