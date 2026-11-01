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

Browser enterprise policies use the same preview, confirmation, stale-state check,
backup, elevated adapter, rollback and restore history as other fixes. The Browser
controls on WebRTC, fingerprint and locale cards and **Harden browsers** apply the
four browser measures together. Preset languages supply the language list;
ApplicationLocaleValue is written only on Windows. Existing WebRtcLocalIpsAllowedUrls
and other unrelated policies remain intact. Firefox preferences are locked.

Detection covers standard Chrome, Edge, Chromium, Brave and Firefox installs.
Linux targets include the system policy file and detected Firefox distribution
folders under `/usr/lib/firefox`, `/usr/lib/firefox-esr`, `/usr/lib64/firefox`, and
`/opt/firefox`; macOS uses `/Applications` bundles and managed preferences;
Windows uses machine policy registry keys and both Program Files Firefox
locations. Portable, Snap/Flatpak and custom install locations are not inferred.
Missing browsers are listed in the preview (or an explicit message if none exist).

Files are backed up as raw bytes, including binary plists, or recorded as absent.
Registry snapshots retain keys, names, types and values, including absence;
updates change only differing values and retain unrelated keys and ACLs. Restore
reinstates the previous bytes/values and deletes resources that were absent.
New Unix policy files are readable (0644); existing file permissions are retained.
Backups remain private and policy previews show only the intended policy keys.

Restart affected browsers after applying or restoring. The offered browser check
starts a fresh scan and opens a new authenticated check page; policy application
alone never changes a check result to Pass. Browser support and effective policy
loading still need verification on actual browser/OS combinations. Tests only
mutate fake adapters and temporary files, never real browser policy locations.

The requested `WebRtcIPHandlingPolicy` key is retained, with the documented
`WebRtcIPHandling` key for Chrome/Chromium/Brave and `WebRtcLocalhostIpHandling`
for Edge also set to `disable_non_proxied_udp`. These vendor keys are included
in the preview and backup/restore scope. References:
[Chromium policy definition](https://chromium.googlesource.com/chromium/src/+/376fc41e87a058f7a7b300b0ec3a4982b4ec0960/components/policy/resources/templates/policy_definitions/Miscellaneous/WebRtcIPHandling.yaml),
[Edge policy reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/WebRtcLocalhostIpHandling).
