package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"
)

func runIPs(client *client, out io.Writer, asJSON bool) error {
	ips, err := client.savedIPs()
	if err != nil {
		return err
	}
	if asJSON {
		type entry struct {
			IP    string `json:"ip"`
			Label string `json:"label"`
		}
		entries := make([]entry, 0, len(ips))
		for _, ip := range ips {
			entries = append(entries, entry{IP: ip.IP, Label: ip.Label})
		}
		return writeJSON(out, entries)
	}
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "IP\tLABEL")
	for _, ip := range ips {
		fmt.Fprintf(table, "%s\t%s\n", ip.IP, ip.Label)
	}
	return table.Flush()
}

func runRules(client *client, out io.Writer, ips []string, asJSON bool) error {
	if len(ips) == 0 {
		var err error
		if ips, err = client.scopeAddresses(); err != nil {
			return err
		}
	}
	ruleset, err := client.ruleset(ips)
	if err != nil {
		return err
	}
	if asJSON {
		return writeRuleset(out, ruleset)
	}
	table := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "IP\tLABEL\tPROTOCOL\tPORT\tSOURCE\tACTION")
	for _, ip := range sortedIPs(ruleset) {
		for _, rule := range ruleset[ip].Rules {
			port := strconv.Itoa(rule.Port)
			if rule.Port == 0 {
				port = "all"
			}
			fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n", ip, ruleset[ip].Label, rule.Protocol, port, rule.Source, rule.Action)
		}
	}
	return table.Flush()
}

func runAttacks(client *client, out io.Writer, ips []string, hours int) error {
	if len(ips) == 0 {
		var response struct {
			Ongoing json.RawMessage `json:"ongoing"`
		}
		if err := client.do("GET", "/api/attacks/ongoing", nil, &response); err != nil {
			return err
		}
		return writeJSON(out, response.Ongoing)
	}
	var response struct {
		Attacks json.RawMessage `json:"attacks"`
	}
	path := fmt.Sprintf("/api/attacks/%s?hours=%d", ips[0], hours)
	if err := client.do("GET", path, nil, &response); err != nil {
		return err
	}
	return writeJSON(out, response.Attacks)
}

func runPlan(client *client, out io.Writer, desired Ruleset, shouldApply bool) error {
	changes, err := client.plan(desired)
	if err != nil {
		return err
	}
	printPlan(out, changes)
	if !shouldApply || len(changes) == 0 {
		return nil
	}

	if err := client.apply(changes); err != nil {
		return err
	}
	remaining, err := client.plan(desired)
	if err != nil {
		return err
	}
	if len(remaining) > 0 {
		fmt.Fprintln(out, "\nStill different after apply:")
		printPlan(out, remaining)
		return errors.New("live firewall does not match after apply")
	}
	fmt.Fprintln(out, "\nApplied.")
	return nil
}

func runSet(client *client, out io.Writer, ip string, rule Rule) error {
	existing, found, err := client.findLiveRule(ip, rule.key())
	if err != nil {
		return err
	}
	if found && isCatchAll(rule) && existing.Action != rule.Action {
		return errors.New("refusing to change a catch-all rule (port 0, source any), change it in the portal instead")
	}
	if !found {
		if err := client.apply([]change{{IP: ip, Kind: addRule, Rule: rule}}); err != nil {
			return err
		}
		fmt.Fprintf(out, "%s: added %s: %s\n", ip, rule, rule.Action)
		return nil
	}
	if existing.Action == rule.Action {
		fmt.Fprintf(out, "%s: %s is already %s\n", ip, rule, rule.Action)
		return nil
	}
	update := change{IP: ip, Kind: updateRule, Rule: rule, PreviousAction: existing.Action, Live: existing}
	if err := client.apply([]change{update}); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s: changed %s: %s -> %s\n", ip, rule, existing.Action, rule.Action)
	return nil
}

func runDelete(client *client, out io.Writer, ip string, rule Rule) error {
	if isCatchAll(rule) {
		return errors.New("refusing to delete a catch-all rule (port 0, source any), change it in the portal instead")
	}
	existing, found, err := client.findLiveRule(ip, rule.key())
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s: no rule for %s", ip, rule)
	}
	rule.Action = existing.Action
	if err := client.apply([]change{{IP: ip, Kind: removeRule, Rule: rule, Live: existing}}); err != nil {
		return err
	}
	fmt.Fprintf(out, "%s: deleted %s: %s\n", ip, rule, rule.Action)
	return nil
}

func isCatchAll(rule Rule) bool {
	return rule.Port == 0 && rule.Source == "any"
}
