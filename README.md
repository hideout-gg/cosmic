# cosmic

Unofficial CLI for the [Cosmic Guard](https://firewall.cosmic.global) firewall portal from Cosmic Global Networks. It reads and writes firewall rules through the same JSON API the portal uses. It is not affiliated with Cosmic, and the API it talks to is undocumented, so it can change without notice.

## Install

```
go install github.com/hideout-gg/cosmic@latest
```

## Usage

```
export COSMIC_USERNAME=... COSMIC_PASSWORD=...

cosmic ips                              # saved IPs
cosmic rules                            # every rule in the account's scope
cosmic rules 203.0.113.10               # one IP
cosmic attacks                          # ongoing attacks
cosmic set 203.0.113.10 tcp 8080 pass   # add a rule or change its action
cosmic delete 203.0.113.10 tcp 8080     # remove a rule
cosmic rules > rules.json               # snapshot as a ruleset file
cosmic plan -f rules.json               # diff a ruleset against live
cosmic apply -f rules.json              # make live match the ruleset
```

Output is a table on a terminal and JSON otherwise, so scripts and agents get JSON by default. Pass `--json` to force it.

Use a portal sub-user without 2FA. Give it only the permissions you need: `rules.view` for reading, plus the add, edit, delete and replace permissions for writing. The login session is cached in your user cache directory, so repeated calls don't log in every time.

## Safety

- Catch-all rules (port 0, source any) can only be added, never changed or removed. `set` and `delete` refuse to touch them, and `plan` and `apply` refuse a ruleset that would change or remove one. Change them in the portal instead.
- `apply` adds rules first and removes them last. It never replaces all of an IP's rules at once, so traffic isn't dropped mid-change.
- `apply` only touches IPs listed in the file.

## Using it in CI

Keep the ruleset in git, run `cosmic plan -f rules.json` on pull requests and `cosmic apply -f rules.json` on your main branch.

## License

MIT
