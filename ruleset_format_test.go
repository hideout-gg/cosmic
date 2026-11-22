package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestWriteRuleset(t *testing.T) {
	tests := []struct {
		name    string
		ruleset Ruleset
		want    string
	}{
		{
			name:    "empty",
			ruleset: Ruleset{},
			want:    "{\n}\n",
		},
		{
			name: "one rule per line, IPs in numeric order",
			ruleset: Ruleset{
				"203.0.113.10": {Label: "web", Rules: []Rule{
					{Port: 0, Protocol: "tcp", Action: "drop", Source: "any"},
					{Port: 443, Protocol: "tcp", Action: "cloudflare-only", Source: "any"},
				}},
				"203.0.113.9": {Rules: []Rule{{Port: 22, Protocol: "tcp", Action: "pass", Source: "198.51.100.7"}}},
			},
			want: `{
  "203.0.113.9": {
    "rules": [
      { "port": 22, "protocol": "tcp", "action": "pass", "source": "198.51.100.7" }
    ]
  },
  "203.0.113.10": {
    "label": "web",
    "rules": [
      { "port": 0, "protocol": "tcp", "action": "drop", "source": "any" },
      { "port": 443, "protocol": "tcp", "action": "cloudflare-only", "source": "any" }
    ]
  }
}
`,
		},
		{
			name:    "IP without rules",
			ruleset: Ruleset{"203.0.113.10": {Label: "empty", Rules: []Rule{}}},
			want:    "{\n  \"203.0.113.10\": {\n    \"label\": \"empty\",\n    \"rules\": []\n  }\n}\n",
		},
		{
			name:    "label needing escapes",
			ruleset: Ruleset{"203.0.113.10": {Label: `quote " and \ slash`, Rules: []Rule{}}},
			want:    "{\n  \"203.0.113.10\": {\n    \"label\": \"quote \\\" and \\\\ slash\",\n    \"rules\": []\n  }\n}\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := writeRuleset(&out, test.ruleset); err != nil {
				t.Fatal(err)
			}
			if out.String() != test.want {
				t.Fatalf("got\n%s\nwant\n%s", out.String(), test.want)
			}
			var parsed Ruleset
			if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}
			if !reflect.DeepEqual(parsed, test.ruleset) {
				t.Errorf("round trip changed the ruleset: got %+v", parsed)
			}
		})
	}
}
