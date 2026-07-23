package main

import (
	"net/http"
	"strings"
)

// Verb-first client API, the Go spelling: the method is the first argument to
// http.NewRequest.
func sendReceipt(form string) (*http.Response, error) {
	req, err := http.NewRequest("POST", "https://api.twilio.com/2010-04-01/Messages.json", strings.NewReader(form))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return http.DefaultClient.Do(req)
}
