package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func writeRuleset(out io.Writer, ruleset Ruleset) error {
	var text strings.Builder
	text.WriteString("{\n")
	ips := sortedIPs(ruleset)
	for i, ip := range ips {
		entry := ruleset[ip]
		fmt.Fprintf(&text, "  %s: {\n", quoted(ip))
		if entry.Label != "" {
			fmt.Fprintf(&text, "    \"label\": %s,\n", quoted(entry.Label))
		}
		if len(entry.Rules) == 0 {
			text.WriteString("    \"rules\": []\n")
		} else {
			text.WriteString("    \"rules\": [\n")
			for j, rule := range entry.Rules {
				fmt.Fprintf(&text, "      { \"port\": %d, \"protocol\": %s, \"action\": %s, \"source\": %s }%s\n",
					rule.Port, quoted(rule.Protocol), quoted(rule.Action), quoted(rule.Source), separator(j, len(entry.Rules)))
			}
			text.WriteString("    ]\n")
		}
		fmt.Fprintf(&text, "  }%s\n", separator(i, len(ips)))
	}
	text.WriteString("}\n")
	_, err := io.WriteString(out, text.String())
	return err
}

func quoted(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func separator(index, length int) string {
	if index < length-1 {
		return ","
	}
	return ""
}
