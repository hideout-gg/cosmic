package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
)

type changeKind string

const (
	addRule    changeKind = "add"
	updateRule changeKind = "update"
	removeRule changeKind = "remove"
)

type change struct {
	IP             string
	Kind           changeKind
	Rule           Rule
	PreviousAction string
	Live           liveRule
}

func (c change) description() string {
	if c.Kind == updateRule {
		return fmt.Sprintf("%s: %s -> %s", c.Rule, c.PreviousAction, c.Rule.Action)
	}
	return fmt.Sprintf("%s: %s", c.Rule, c.Rule.Action)
}

func (c change) String() string {
	symbols := map[changeKind]string{addRule: "+", updateRule: "~", removeRule: "-"}
	return fmt.Sprintf("  %s %s", symbols[c.Kind], c.description())
}

func readRuleset(path string) (Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ruleset Ruleset
	if err := json.Unmarshal(data, &ruleset); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ruleset, nil
}

func validateRuleset(ruleset Ruleset) error {
	for _, ip := range sortedIPs(ruleset) {
		if err := validateIPs([]string{ip}); err != nil {
			return err
		}
		seen := map[ruleKey]bool{}
		for i, rule := range ruleset[ip].Rules {
			protocol := normalizeProtocol(rule.Protocol)
			if protocol == "" {
				return fmt.Errorf("%s: unknown protocol %q", ip, rule.Protocol)
			}
			if rule.Port < 0 || rule.Port > 65535 {
				return fmt.Errorf("%s: port %d out of range", ip, rule.Port)
			}
			if rule.Action == "" {
				return fmt.Errorf("%s: %s has no action", ip, rule)
			}
			rule.Protocol = protocol
			rule.Source = normalizeSource(rule.Source)
			if !validSource(rule.Source) {
				return fmt.Errorf("%s: invalid source %q", ip, rule.Source)
			}
			ruleset[ip].Rules[i] = rule
			if seen[rule.key()] {
				return fmt.Errorf("%s: %s is listed twice", ip, rule)
			}
			seen[rule.key()] = true
		}
	}
	return nil
}

func planChanges(desired Ruleset, live map[string][]liveRule) ([]change, error) {
	var adds, updates, removes []change
	for _, ip := range sortedIPs(desired) {
		type existingRule struct {
			raw  liveRule
			rule Rule
		}
		liveByKey := map[ruleKey]existingRule{}
		for _, raw := range live[ip] {
			rule, err := raw.normalized()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", ip, err)
			}
			if _, duplicate := liveByKey[rule.key()]; duplicate {
				removes = append(removes, change{IP: ip, Kind: removeRule, Rule: rule, Live: raw})
				continue
			}
			liveByKey[rule.key()] = existingRule{raw: raw, rule: rule}
		}

		wanted := map[ruleKey]bool{}
		for _, rule := range desired[ip].Rules {
			wanted[rule.key()] = true
			existing, found := liveByKey[rule.key()]
			switch {
			case !found:
				adds = append(adds, change{IP: ip, Kind: addRule, Rule: rule})
			case existing.rule.Action != rule.Action:
				updates = append(updates, change{IP: ip, Kind: updateRule, Rule: rule, PreviousAction: existing.rule.Action, Live: existing.raw})
			}
		}

		var extra []change
		for key, existing := range liveByKey {
			if !wanted[key] {
				extra = append(extra, change{IP: ip, Kind: removeRule, Rule: existing.rule, Live: existing.raw})
			}
		}
		sort.Slice(extra, func(i, j int) bool { return extra[i].Rule.String() < extra[j].Rule.String() })
		removes = append(removes, extra...)
	}
	changes := append(append(adds, updates...), removes...)
	for _, change := range changes {
		if change.Kind != addRule && isCatchAll(change.Rule) {
			return nil, fmt.Errorf("%s: refusing to %s catch-all rule %s, change it in the portal instead", change.IP, change.Kind, change.description())
		}
	}
	return changes, nil
}

func (c *client) plan(desired Ruleset) ([]change, error) {
	live := map[string][]liveRule{}
	for _, ip := range sortedIPs(desired) {
		rules, err := c.liveRules(ip)
		if err != nil {
			return nil, err
		}
		live[ip] = rules
	}
	return planChanges(desired, live)
}

func (c *client) apply(changes []change) error {
	addsByIP := map[string][]map[string]string{}
	var addOrder []string
	for _, change := range changes {
		if change.Kind != addRule {
			continue
		}
		if _, seen := addsByIP[change.IP]; !seen {
			addOrder = append(addOrder, change.IP)
		}
		addsByIP[change.IP] = append(addsByIP[change.IP], requestRule(change.Rule))
	}
	for _, ip := range addOrder {
		if err := c.do("PATCH", "/api/rules/"+ip, map[string]any{"rules": addsByIP[ip]}, nil); err != nil {
			return err
		}
	}

	for _, change := range changes {
		switch change.Kind {
		case updateRule:
			body := requestRule(change.Rule)
			body["original_rule"] = change.PreviousAction
			if _, hasSource := body["src_ip"]; !hasSource {
				body["src_ip"] = ""
			}
			if err := c.do("PUT", change.Live.path(change.IP), body, nil); err != nil {
				return err
			}
		case removeRule:
			if err := c.do("DELETE", change.Live.path(change.IP), nil, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func requestRule(rule Rule) map[string]string {
	body := map[string]string{
		"dst_port": strconv.Itoa(rule.Port),
		"protocol": rule.Protocol,
		"rule":     rule.Action,
	}
	if rule.Source != "any" {
		body["src_ip"] = rule.Source
	}
	return body
}

func printPlan(out io.Writer, changes []change) {
	if len(changes) == 0 {
		fmt.Fprintln(out, "No changes.")
		return
	}
	counts := map[changeKind]int{}
	byIP := map[string][]change{}
	for _, change := range changes {
		counts[change.Kind]++
		byIP[change.IP] = append(byIP[change.IP], change)
	}
	for _, ip := range sortedIPs(byIP) {
		fmt.Fprintln(out, ip)
		for _, change := range byIP[ip] {
			fmt.Fprintln(out, change)
		}
	}
	fmt.Fprintf(out, "\nPlan: %d to add, %d to change, %d to remove.\n", counts[addRule], counts[updateRule], counts[removeRule])
}
