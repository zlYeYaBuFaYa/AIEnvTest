# System fix transactions

The frontend sends a check ID and receives an opaque plan ID. It cannot submit
commands or file paths. Plans show the captured state and proposed changes.
The transaction engine takes a versioned, sealed backup before writing, rejects
stale previews, records step failures, and attempts rollback. Both single restore
and restore-all accept the new typed resources.

| Fix | Linux / Ubuntu | macOS | Windows |
| --- | --- | --- | --- |
| Language / region | `localectl set-locale`; exact locale-file backups | User `AppleLanguages` and `AppleLocale` via defaults | User language list (including keyboard tips), culture, and home GeoID |
| DNS | NetworkManager active connection UUIDs; modify and device reapply | Active network services via networksetup | Active adapter GUIDs, resolved to current interface indices |
| IPv6 | Physical sysfs devices; per-interface runtime sysctl and dedicated drop-in | Hardware-port services, preserving automatic/manual/link-local/off modes | Physical adapter GUIDs; ms_tcpip6 binding |
| UDP | Dedicated `inet aienv` nftables table | Dedicated `com.apple/com.aienv` PF anchor | Individually named rules in firewall group `AIEnv` |
| Proxy bypass | GNOME gsettings ignore-hosts | Per-service networksetup bypass domains | HKCU ProxyOverride |
| Location | Explicit settings guidance | Explicit settings guidance | ConsentStore Value=Deny, HKCU; HKLM as a separate resource when already elevated |

Language changes require signing out and back in. The Linux language plan
preserves `/etc/locale.conf` and `/etc/default/locale`, including absent files,
and restores localed's original locale variables. Unsupported file contents or
unavailable localed/NetworkManager/GNOME services produce a refusal. User-level
preferences run in the original caller's account even in a mixed restore-all.

DNS plans require an exit_ipv4 Pass with the selected country's explicit country
observation in a report no older than 120 seconds. Future timestamps and region
mismatches are rejected. The gate is checked at preview and again before apply.
Previous per-interface automatic/empty settings are preserved. Windows uses GUIDs
to avoid restoring into a recycled interface index. Restore refuses if a required
interface is no longer available.

UDP preview requires the actual tunnel endpoint IP/UDP port and tunnel DNS
resolver IP. The scan does not collect sufficient endpoint information to guess
these safely. TCP traffic and tunnel interfaces are not blocked. On physical
interfaces the policy permits only DHCP (correct source/destination port and
address family), DNS to the specified resolver, and UDP to the specified tunnel
endpoint; other UDP, including QUIC, is blocked. Changes to tunnel endpoints need
an updated policy (restore the previous policy first).

The firewall manifest records ownership before rules are installed, permitting
rollback after a partial write. Restore deletes the owned nftables table only
after checking its contents, flushes only the owned PF anchor, or deletes the
exact generated Windows rule names. Unknown contents cause refusal; shared
rulesets and the Windows firewall group are never flushed. PF enablement uses a
reference token and restore releases that token. PF needs an existing reachable
standard `com.apple/*` filter-anchor hook; the implementation does not reload the
machine's main ruleset. Earlier quick rules or other earlier anchors cause a
conservative refusal. PF state lookup happens before rule evaluation. Installation therefore refuses
existing UDP states whose destinations are not verified tunnel/DNS/DHCP
exceptions; close the affected applications and allow their states to expire
before retrying. Tunnel states are never flushed.
The policy currently applies to the physical adapters captured in the preview;
new hardware requires a new policy.

On modern macOS, even `systemsetup -getusingnetworktime` requires root. The adapter
now uses an integrity-checked, allowlisted read-only helper request for that
snapshot. Such a request cannot execute its placeholder write step. Declining
authorization refuses the fix rather than inventing the original enabled state.
NTP restore restores enablement, not historical wall-clock time.

Tests execute no system mutation commands. Fake adapters cover each fix on each
applicable OS, command generation and cleanup, sealed backups and both restore
paths. The settings writer is injectable: locale and sysctl drop-in writes are
exercised in temporary directories. Native command behavior and interactive
privilege prompts still require OS smoke testing on actual machines.
