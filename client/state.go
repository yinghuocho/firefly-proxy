package main

import (
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type fireflyState struct {
	trackingID string
	clientID   string
	httpClient *http.Client
	ch         chan string
}

func newState(clientID string, trackingID string, proxyURL *url.URL) *fireflyState {
	return &fireflyState{
		trackingID: trackingID,
		clientID:   clientID,
		httpClient: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
			Timeout: time.Minute,
		},
		ch: make(chan string, 10),
	}
}

func (s *fireflyState) reportEvent(category, action, label, value string) {
	log.Printf("report google analytics event: [%s %s]", category, action)
	resp, err := s.httpClient.PostForm("https://www.google-analytics.com/collect", url.Values{
		"v":   {"1"},
		"tid": {s.trackingID},
		"cid": {s.clientID},
		"an":  {"Firefly"},
		"ua":  {strings.Join([]string{runtime.GOOS, runtime.GOARCH}, "_")},
		"av":  {FIREFLY_VERSION},
		"t":   {"event"},
		"ec":  {category},
		"ea":  {action},
		"el":  {label},
		"ev":  {value},
	})
	if err != nil {
		log.Printf("error to report google analytics event: %s", err)
	} else {
		resp.Body.Close()
	}
}

func (s *fireflyState) event(category string, action string, label string, value int) {
	s.ch <- strings.Join([]string{"event", category, action, label, strconv.Itoa(value)}, "|")
}

func (s *fireflyState) run() {
	for {
		cmd := <-s.ch
		switch {
		case strings.HasPrefix(cmd, "event"):
			args := strings.Split(cmd, "|")
			s.reportEvent(args[1], args[2], args[3], args[4])
		}
	}
}
