package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type Rule struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
	Source   string `json:"source"`
}

type IPRules struct {
	Label string `json:"label,omitempty"`
	Rules []Rule `json:"rules"`
}

type Ruleset map[string]IPRules

type ruleKey struct {
	Protocol string
	Port     int
	Source   string
}

func (r Rule) key() ruleKey {
	return ruleKey{Protocol: r.Protocol, Port: r.Port, Source: r.Source}
}

func (r Rule) String() string {
	port := strconv.Itoa(r.Port)
	if r.Port == 0 {
		port = "all"
	}
	return fmt.Sprintf("%s %s from %s", r.Protocol, port, r.Source)
}

func sortRules(rules []Rule) {
	sort.Slice(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Source < b.Source
	})
}

type looseString string

func (s *looseString) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		*s = ""
		return nil
	}
	if len(data) > 0 && data[0] == '"' {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
		*s = looseString(text)
		return nil
	}
	*s = looseString(data)
	return nil
}

type liveRule struct {
	Source   looseString `json:"src_ip"`
	Port     looseString `json:"dst_port"`
	Protocol looseString `json:"protocol"`
	Action   string      `json:"rule"`
}

func (r liveRule) normalized() (Rule, error) {
	port, err := strconv.Atoi(string(r.Port))
	if err != nil {
		return Rule{}, fmt.Errorf("unexpected port %q", r.Port)
	}
	protocol := normalizeProtocol(string(r.Protocol))
	if protocol == "" {
		return Rule{}, fmt.Errorf("unexpected protocol %q", r.Protocol)
	}
	return Rule{Port: port, Protocol: protocol, Action: r.Action, Source: normalizeSource(string(r.Source))}, nil
}

func (r liveRule) path(ip string) string {
	path := fmt.Sprintf("/api/rules/%s/%s/%s", ip, url.PathEscape(string(r.Port)), url.PathEscape(string(r.Protocol)))
	if r.Source != "" {
		path += "/" + url.PathEscape(string(r.Source))
	}
	return path
}

func normalizeProtocol(protocol string) string {
	switch strings.ToLower(protocol) {
	case "tcp", "6":
		return "tcp"
	case "udp", "17":
		return "udp"
	case "icmp", "1":
		return "icmp"
	case "gre", "47":
		return "gre"
	}
	return ""
}

func normalizeSource(source string) string {
	switch source {
	case "", "0", "0.0.0.0", "any":
		return "any"
	}
	return source
}

func (c *client) liveRules(ip string) ([]liveRule, error) {
	var raw json.RawMessage
	if err := c.do("GET", "/api/rules/"+ip, nil, &raw); err != nil {
		return nil, err
	}
	var rules []liveRule
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) {
		return rules, json.Unmarshal(raw, &rules)
	}
	var wrapped struct {
		Result []liveRule `json:"result"`
	}
	return wrapped.Result, json.Unmarshal(raw, &wrapped)
}

type savedIP struct {
	IP    string `json:"ip_address"`
	Label string `json:"label"`
}

func (c *client) savedIPs() ([]savedIP, error) {
	var response struct {
		IPs []savedIP `json:"ips"`
	}
	if err := c.do("GET", "/api/ips", nil, &response); err != nil {
		return nil, err
	}
	sort.Slice(response.IPs, func(i, j int) bool { return lessIP(response.IPs[i].IP, response.IPs[j].IP) })
	return response.IPs, nil
}

func (c *client) findLiveRule(ip string, key ruleKey) (liveRule, bool, error) {
	live, err := c.liveRules(ip)
	if err != nil {
		return liveRule{}, false, err
	}
	for _, raw := range live {
		rule, err := raw.normalized()
		if err != nil {
			return liveRule{}, false, fmt.Errorf("%s: %w", ip, err)
		}
		if rule.key() == key {
			return raw, true, nil
		}
	}
	return liveRule{}, false, nil
}

func (c *client) scopeAddresses() ([]string, error) {
	var response struct {
		Scope []string `json:"scope"`
	}
	if err := c.do("GET", "/api/rules/prefixes", nil, &response); err != nil {
		return nil, err
	}
	var addresses []string
	for _, cidr := range response.Scope {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("unexpected scope %q", cidr)
		}
		for address := prefix.Masked().Addr(); prefix.Contains(address); address = address.Next() {
			addresses = append(addresses, address.String())
		}
	}
	return addresses, nil
}

func (c *client) ruleset(ips []string) (Ruleset, error) {
	saved, err := c.savedIPs()
	if err != nil {
		return nil, err
	}
	labels := map[string]string{}
	for _, ip := range saved {
		labels[ip.IP] = ip.Label
	}

	ruleset := Ruleset{}
	for _, ip := range ips {
		live, err := c.liveRules(ip)
		if err != nil {
			return nil, err
		}
		if len(live) == 0 {
			continue
		}
		rules := make([]Rule, 0, len(live))
		for _, rule := range live {
			normalized, err := rule.normalized()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", ip, err)
			}
			rules = append(rules, normalized)
		}
		sortRules(rules)
		ruleset[ip] = IPRules{Label: labels[ip], Rules: rules}
	}
	return ruleset, nil
}
