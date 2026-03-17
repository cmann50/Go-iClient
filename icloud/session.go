package icloud

import (
	"encoding/json"
	"net/url"

	http "github.com/bogdanfinn/fhttp"
)

// SessionState holds all auth state needed to resume a session without 2FA.
type SessionState struct {
	AuthToken  string            `json:"auth_token"`
	TrustToken string            `json:"trust_token"`
	FrameID    string            `json:"frame_id"`
	ClientID   string            `json:"client_id"`
	AuthAttr   string            `json:"auth_attr"`
	SessionID  string            `json:"session_id"`
	Scnt       string            `json:"scnt"`
	Dsid       string            `json:"dsid"`
	AccountURL string            `json:"account_url"`
	Cookies    map[string][]Cookie `json:"cookies"`
}

// Cookie is a serializable cookie.
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Path  string `json:"path"`
}

var cookieDomains = []string{
	"https://idmsa.apple.com",
	"https://www.icloud.com",
	"https://icloud.com",
	"https://setup.icloud.com",
}

// ExportSession returns the current session state as JSON bytes.
func (c *Client) ExportSession() ([]byte, error) {
	state := SessionState{
		AuthToken:  c.authToken,
		TrustToken: c.trustToken,
		FrameID:    c.frameId,
		ClientID:   c.clientId,
		AuthAttr:   c.authAttr,
		SessionID:  c.sessionID,
		Scnt:       c.scnt,
		Dsid:       c.dsid,
		AccountURL: c.accountURL,
		Cookies:    make(map[string][]Cookie),
	}

	for _, domain := range cookieDomains {
		u, _ := url.Parse(domain)
		for _, hc := range c.HttpClient.GetCookies(u) {
			state.Cookies[domain] = append(state.Cookies[domain], Cookie{
				Name:  hc.Name,
				Value: hc.Value,
				Path:  hc.Path,
			})
		}
	}

	return json.MarshalIndent(state, "", "  ")
}

// ImportSession restores a previously exported session state.
// After importing, call ValidateSession to check if it's still valid.
// If valid, the client can make API calls without Login.
func (c *Client) ImportSession(data []byte) error {
	var state SessionState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	c.authToken = state.AuthToken
	c.trustToken = state.TrustToken
	c.frameId = state.FrameID
	c.clientId = state.ClientID
	c.authAttr = state.AuthAttr
	c.sessionID = state.SessionID
	c.scnt = state.Scnt
	c.dsid = state.Dsid
	c.accountURL = state.AccountURL

	for domain, cookies := range state.Cookies {
		u, _ := url.Parse(domain)
		var hcs []*http.Cookie
		for _, sc := range cookies {
			hcs = append(hcs, &http.Cookie{
				Name:  sc.Name,
				Value: sc.Value,
				Path:  sc.Path,
			})
		}
		c.HttpClient.SetCookies(u, hcs)
	}

	return nil
}
