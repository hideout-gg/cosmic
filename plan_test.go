package main

import (
	"encoding/json"
	"strings"
	"testing"
)

const ip = "203.0.113.10"

var catchAllDrops = []Rule{
	{Port: 0, Protocol: "tcp", Action: "drop", Source: "any"},
	{Port: 0, Protocol: "udp", Action: "drop", Source: "any"},
}

var liveCatchAllDrops = []liveRule{
	{Source: "0", Port: "0", Protocol: "tcp", Action: "drop"},
	{Source: "0", Port: "0", Protocol: "udp", Action: "drop"},
}

func withDrops(rules ...Rule) []Rule {
	return append(append([]Rule{}, catchAllDrops...), rules...)
}

func withLiveDrops(rules ...liveRule) []liveRule {
	return append(append([]liveRule{}, liveCatchAllDrops...), rules...)
}

func TestPlanChanges(t *testing.T) {
	java := Rule{Port: 25565, Protocol: "tcp", Action: "minecraft-java", Source: "any"}
	liveJava := liveRule{Source: "0", Port: "25565", Protocol: "tcp", Action: "minecraft-java"}

	tests := []struct {
		name    string
		desired []Rule
		live    []liveRule
		want    []string
	}{
		{
			name:    "matching rules need no changes",
			desired: withDrops(java),
			live:    withLiveDrops(liveJava),
			want:    nil,
		},
		{
			name:    "missing rule is added",
			desired: withDrops(java),
			live:    withLiveDrops(),
			want:    []string{"add tcp 25565 from any"},
		},
		{
			name:    "different action is updated",
			desired: withDrops(Rule{Port: 25565, Protocol: "tcp", Action: "pass", Source: "any"}),
			live:    withLiveDrops(liveJava),
			want:    []string{"update tcp 25565 from any"},
		},
		{
			name:    "unlisted rule is removed",
			desired: withDrops(),
			live:    withLiveDrops(liveJava),
			want:    []string{"remove tcp 25565 from any"},
		},
		{
			name:    "duplicate live rule is removed",
			desired: withDrops(java),
			live:    withLiveDrops(liveJava, liveJava),
			want:    []string{"remove tcp 25565 from any"},
		},
		{
			name:    "numeric protocol matches its name",
			desired: withDrops(java),
			live:    withLiveDrops(liveRule{Source: "0", Port: "25565", Protocol: "6", Action: "minecraft-java"}),
			want:    nil,
		},
		{
			name:    "empty source matches any",
			desired: withDrops(java),
			live:    withLiveDrops(liveRule{Source: "", Port: "25565", Protocol: "tcp", Action: "minecraft-java"}),
			want:    nil,
		},
		{
			name:    "zero address source matches any",
			desired: withDrops(java),
			live:    withLiveDrops(liveRule{Source: "0.0.0.0", Port: "25565", Protocol: "tcp", Action: "minecraft-java"}),
			want:    nil,
		},
		{
			name:    "rules with different sources are separate",
			desired: withDrops(java, Rule{Port: 25565, Protocol: "tcp", Action: "pass", Source: "10.0.0.0/8"}),
			live:    withLiveDrops(liveJava),
			want:    []string{"add tcp 25565 from 10.0.0.0/8"},
		},
		{
			name:    "adds come before updates and removes",
			desired: withDrops(Rule{Port: 19132, Protocol: "udp", Action: "minecraft-bedrock", Source: "any"}, Rule{Port: 8192, Protocol: "tcp", Action: "drop", Source: "any"}),
			live:    withLiveDrops(liveJava, liveRule{Source: "0", Port: "8192", Protocol: "tcp", Action: "pass"}),
			want:    []string{"add udp 19132 from any", "update tcp 8192 from any", "remove tcp 25565 from any"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changes, err := planChanges(Ruleset{ip: {Rules: test.desired}}, map[string][]liveRule{ip: test.live})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, change := range changes {
				got = append(got, string(change.Kind)+" "+change.Rule.String())
			}
			if strings.Join(got, "\n") != strings.Join(test.want, "\n") {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestPlanChangesLeavesUnlistedIPsAlone(t *testing.T) {
	live := map[string][]liveRule{
		ip:             withLiveDrops(),
		"203.0.113.11": {{Source: "0", Port: "25565", Protocol: "tcp", Action: "pass"}},
	}
	changes, err := planChanges(Ruleset{ip: {Rules: withDrops()}}, live)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Errorf("got %d changes, want none", len(changes))
	}
}

func TestValidateRuleset(t *testing.T) {
	tests := []struct {
		name    string
		rules   []Rule
		wantErr string
	}{
		{name: "both catch-all drops", rules: withDrops()},
		{name: "missing tcp drop", rules: catchAllDrops[1:], wantErr: "catch-all tcp drop"},
		{name: "missing udp drop", rules: catchAllDrops[:1], wantErr: "catch-all udp drop"},
		{name: "no rules", rules: nil, wantErr: "catch-all tcp drop"},
		{
			name:    "catch-all set to pass",
			rules:   []Rule{{Port: 0, Protocol: "tcp", Action: "pass", Source: "any"}, catchAllDrops[1]},
			wantErr: "catch-all tcp drop",
		},
		{
			name:    "duplicate rule",
			rules:   withDrops(Rule{Port: 80, Protocol: "tcp", Action: "pass", Source: "any"}, Rule{Port: 80, Protocol: "TCP", Action: "drop", Source: ""}),
			wantErr: "listed twice",
		},
		{name: "unknown protocol", rules: withDrops(Rule{Port: 80, Protocol: "sctp", Action: "pass"}), wantErr: "unknown protocol"},
		{name: "port out of range", rules: withDrops(Rule{Port: 70000, Protocol: "tcp", Action: "pass"}), wantErr: "out of range"},
		{name: "missing action", rules: withDrops(Rule{Port: 80, Protocol: "tcp"}), wantErr: "no action"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRuleset(Ruleset{ip: {Rules: test.rules}})
			switch {
			case test.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)):
				t.Fatalf("got error %v, want one containing %q", err, test.wantErr)
			}
		})
	}
}

func TestLooseStringAcceptsNumbers(t *testing.T) {
	tests := []struct {
		json string
		want liveRule
	}{
		{json: `{"src_ip":"0","dst_port":"25565","protocol":"tcp","rule":"pass"}`, want: liveRule{Source: "0", Port: "25565", Protocol: "tcp", Action: "pass"}},
		{json: `{"src_ip":0,"dst_port":25565,"protocol":6,"rule":"pass"}`, want: liveRule{Source: "0", Port: "25565", Protocol: "6", Action: "pass"}},
		{json: `{"src_ip":null,"dst_port":"0","protocol":"udp","rule":"drop"}`, want: liveRule{Source: "", Port: "0", Protocol: "udp", Action: "drop"}},
	}
	for _, test := range tests {
		t.Run(test.json, func(t *testing.T) {
			var got liveRule
			if err := json.Unmarshal([]byte(test.json), &got); err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("got %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestLiveRulePath(t *testing.T) {
	tests := []struct {
		rule liveRule
		want string
	}{
		{rule: liveRule{Source: "0", Port: "25565", Protocol: "tcp"}, want: "/api/rules/" + ip + "/25565/tcp/0"},
		{rule: liveRule{Source: "", Port: "25565", Protocol: "tcp"}, want: "/api/rules/" + ip + "/25565/tcp"},
		{rule: liveRule{Source: "10.0.0.0/8", Port: "22", Protocol: "tcp"}, want: "/api/rules/" + ip + "/22/tcp/10.0.0.0%2F8"},
	}
	for _, test := range tests {
		t.Run(test.want, func(t *testing.T) {
			if got := test.rule.path(ip); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}
