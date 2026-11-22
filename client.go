package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const baseURL = "https://firewall.cosmic.global"

var errNotAuthenticated = errors.New("not authenticated")

type client struct {
	username    string
	password    string
	cookie      string
	sessionPath string
	http        *http.Client
}

func newClient() (*client, error) {
	username := os.Getenv("COSMIC_USERNAME")
	password := os.Getenv("COSMIC_PASSWORD")
	if username == "" || password == "" {
		return nil, errors.New("set COSMIC_USERNAME and COSMIC_PASSWORD")
	}

	c := &client{
		username: username,
		password: password,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
	if cacheDir, err := os.UserCacheDir(); err == nil {
		c.sessionPath = filepath.Join(cacheDir, "cosmic", "session-"+username)
		if saved, err := os.ReadFile(c.sessionPath); err == nil {
			c.cookie = strings.TrimSpace(string(saved))
		}
	}
	return c, nil
}

func (c *client) do(method, path string, body, out any) error {
	if c.cookie == "" {
		if err := c.login(); err != nil {
			return err
		}
	}
	err := c.send(method, path, body, out)
	if errors.Is(err, errNotAuthenticated) {
		if err := c.login(); err != nil {
			return err
		}
		err = c.send(method, path, body, out)
	}
	return err
}

func (c *client) send(method, path string, body, out any) error {
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		requestBody = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, baseURL+path, requestBody)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return errNotAuthenticated
	}
	if resp.StatusCode >= 300 {
		var apiError struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &apiError) == nil && apiError.Error != "" {
			return fmt.Errorf("%s %s: %s", method, path, apiError.Error)
		}
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *client) login() error {
	c.cookie = ""
	credentials := map[string]string{"username": c.username, "password": c.password}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		return err
	}

	resp, err := c.http.Post(baseURL+"/api/auth/login", "application/json", bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result struct {
		Error         string `json:"error"`
		TwofaRequired bool   `json:"twofa_required"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("login failed: %s %s", resp.Status, result.Error)
	}
	if result.TwofaRequired {
		return errors.New("login needs 2FA, use an account without it")
	}

	var cookies []string
	for _, cookie := range resp.Cookies() {
		cookies = append(cookies, cookie.Name+"="+cookie.Value)
	}
	c.cookie = strings.Join(cookies, "; ")

	if c.sessionPath != "" {
		if err := os.MkdirAll(filepath.Dir(c.sessionPath), 0o700); err == nil {
			_ = os.WriteFile(c.sessionPath, []byte(c.cookie), 0o600)
		}
	}
	return nil
}
