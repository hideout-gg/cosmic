package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
)

const usage = `usage: cosmic <command> [flags]

  ips                   list the account's saved IPs
  rules [ip...]         show firewall rules, for every IP in scope by default
  attacks [ip]          show ongoing attacks, or one IP's recent attacks (--hours, default 24)
  plan -f rules.json    show what apply would change
  apply -f rules.json   make the live firewall match rules.json
  set <ip> <protocol> <port> <action> [--source ip]
                        add a rule, or change the action of an existing one
  delete <ip> <protocol> <port> [--source ip]
                        remove one rule

Port 0 means every port. Actions include pass, drop, cloudflare-only, minecraft-java and minecraft-bedrock.
A source is a single IP or any. Cosmic does not accept ranges.
Catch-all rules (port 0, source any) can be added but never changed or removed.
Credentials come from COSMIC_USERNAME and COSMIC_PASSWORD.
ips and rules print a table on a terminal and JSON otherwise. Pass --json to force JSON.
The JSON from "cosmic rules" is the format plan and apply read.
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "cosmic:", err)
		os.Exit(1)
	}
}

type commandFunc func(client *client) error

func run(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(out, usage)
		return nil
	}
	command, err := parseCommand(args, out)
	if err != nil {
		return err
	}
	client, err := newClient()
	if err != nil {
		return err
	}
	return command(client)
}

func parseCommand(args []string, out io.Writer) (commandFunc, error) {
	name := args[0]
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	forceJSON := flags.Bool("json", false, "print JSON")
	file := flags.String("f", "", "ruleset file")
	hours := flags.Int("hours", 24, "attack history window in hours")
	source := flags.String("source", "any", "source IP")
	positional, err := parseInterleaved(flags, args[1:])
	if err != nil {
		return nil, err
	}
	asJSON := *forceJSON || !isTerminal(out)

	switch name {
	case "ips":
		if len(positional) != 0 {
			return nil, errors.New("usage: cosmic ips")
		}
		return func(c *client) error { return runIPs(c, out, asJSON) }, nil

	case "rules":
		if err := validateIPs(positional); err != nil {
			return nil, err
		}
		return func(c *client) error { return runRules(c, out, positional, asJSON) }, nil

	case "attacks":
		if len(positional) > 1 {
			return nil, errors.New("usage: cosmic attacks [ip] [--hours n]")
		}
		if err := validateIPs(positional); err != nil {
			return nil, err
		}
		if *hours < 1 {
			return nil, errors.New("--hours must be at least 1")
		}
		return func(c *client) error { return runAttacks(c, out, positional, *hours) }, nil

	case "plan", "apply":
		if *file == "" || len(positional) != 0 {
			return nil, fmt.Errorf("usage: cosmic %s -f rules.json", name)
		}
		desired, err := readRuleset(*file)
		if err != nil {
			return nil, err
		}
		if err := validateRuleset(desired); err != nil {
			return nil, err
		}
		shouldApply := name == "apply"
		return func(c *client) error { return runPlan(c, out, desired, shouldApply) }, nil

	case "set":
		if len(positional) != 4 {
			return nil, errors.New("usage: cosmic set <ip> <protocol> <port> <action> [--source ip]")
		}
		ip, rule, err := ruleFromArgs(positional[0], positional[1], positional[2], positional[3], *source)
		if err != nil {
			return nil, err
		}
		return func(c *client) error { return runSet(c, out, ip, rule) }, nil

	case "delete":
		if len(positional) != 3 {
			return nil, errors.New("usage: cosmic delete <ip> <protocol> <port> [--source ip]")
		}
		ip, rule, err := ruleFromArgs(positional[0], positional[1], positional[2], "", *source)
		if err != nil {
			return nil, err
		}
		return func(c *client) error { return runDelete(c, out, ip, rule) }, nil
	}
	return nil, fmt.Errorf("unknown command %q, run \"cosmic help\"", name)
}

func parseInterleaved(flags *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		args = flags.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func validateIPs(ips []string) error {
	for _, ip := range ips {
		if _, err := netip.ParseAddr(ip); err != nil {
			return fmt.Errorf("invalid IP %q", ip)
		}
	}
	return nil
}

func ruleFromArgs(ip, protocol, port, action, source string) (string, Rule, error) {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return "", Rule{}, fmt.Errorf("invalid IP %q", ip)
	}
	normalizedProtocol := normalizeProtocol(protocol)
	if normalizedProtocol == "" {
		return "", Rule{}, fmt.Errorf("unknown protocol %q", protocol)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 0 || portNumber > 65535 {
		return "", Rule{}, fmt.Errorf("invalid port %q", port)
	}
	normalizedSource := normalizeSource(source)
	if !validSource(normalizedSource) {
		return "", Rule{}, fmt.Errorf("invalid source %q", source)
	}
	return address.String(), Rule{Port: portNumber, Protocol: normalizedProtocol, Action: action, Source: normalizedSource}, nil
}

func validSource(source string) bool {
	if source == "any" {
		return true
	}
	_, err := netip.ParseAddr(source)
	return err == nil
}

func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func isTerminal(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func lessIP(a, b string) bool {
	addressA, errA := netip.ParseAddr(a)
	addressB, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a < b
	}
	return addressA.Less(addressB)
}

func sortedIPs[V any](byIP map[string]V) []string {
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return lessIP(ips[i], ips[j]) })
	return ips
}
