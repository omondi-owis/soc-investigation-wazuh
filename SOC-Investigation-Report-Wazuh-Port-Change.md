# SOC Investigation Report: Wazuh Port-Change Alert

**Document Type:** Security Operations Centre (SOC) Investigation Report  
**Investigation Category:** Host-Based Security Monitoring  
**Severity:** Medium — Initial triage priority  
**Status:** Initial investigation completed; further validation recommended  
**Environment:** Isolated cybersecurity lab  
**Monitoring Platform:** Wazuh  
**Endpoint Operating System:** Ubuntu Server  
**Investigation Date:** 13 October 2026  
**Analyst:** SOC Lab Analyst  
**Case Reference:** SOC-2026-001  

---

## 1. Executive Summary

This report documents the investigation of a Wazuh security alert generated after a change in the listening-port inventory of an Ubuntu Server endpoint.

Wazuh generated **Rule ID 533**, with a severity level of 7, describing a change in listening-port status. The alert contained previous and current snapshots of network listeners, allowing the analyst to identify changes in the host's network configuration.

The investigation involved reviewing the Wazuh alert, examining current listening ports using the Linux `ss` utility, checking the host firewall using Uncomplicated Firewall (UFW), and identifying services running on the endpoint.

The investigation identified SSH listening on all IPv4 and IPv6 interfaces. UFW permitted inbound SSH, HTTP, and HTTPS traffic, while Ollama access was permitted from a specified private subnet. The current listener inventory showed that port 443 was associated with Tailscale, while no TCP listeners were observed on ports 80 or 11434 during the checks.

The MlinziOps application was observed listening on the loopback address at port 8000, and PostgreSQL was listening on the loopback address at port 5432. These bindings limit direct access through the endpoint's other network interfaces.

The available evidence did not establish that the port changes were malicious. The alert was therefore treated as a change requiring contextual investigation rather than a confirmed security incident.

Further validation of SSH authentication activity, firewall exposure, and the necessity of running services was identified as the next step.

## 2. Investigation Objectives

The objectives of this investigation were to:

1. Investigate the Wazuh alert concerning changes to listening ports.
2. Correlate the alert with the endpoint's current network-listening state.
3. Review firewall rules and identify potentially exposed services.
4. Document findings, assess risk, and recommend appropriate defensive actions.

## 3. Environment and Tools

The investigation was conducted in a personal cybersecurity lab consisting of an Ubuntu Server endpoint monitored by a Wazuh manager.

The following tools and components were used:

| Tool or component | Purpose |
|---|---|
| Wazuh Manager | Centralized security-event collection and alert generation |
| Wazuh Agent | Endpoint monitoring and event forwarding |
| Ubuntu Server | Investigated endpoint |
| `ss` | Inspection of current TCP and UDP listeners |
| UFW | Review of host-based firewall policy |
| `systemctl` | Verification of service activity |
| Linux system logs | Investigation of authentication and service events |
| MlinziOps | Security monitoring project running on the endpoint |

## 4. Alert Details

The primary alert was recorded with the following attributes:

| Attribute | Observed value |
|---|---|
| Rule ID | 533 |
| Rule description | Listened ports status changed (new port opened or closed) |
| Rule severity | 7 |
| Affected agent | `ubuntu-server` |
| Agent ID | `001` |
| Recorded timestamp | 2026-10-13 13:15:07 UTC |
| Detection category | Host monitoring / listening-port change |
| Initial disposition | Requires investigation |

The alert contained both previous and current listening-port snapshots. Comparing these snapshots showed differences in network listeners and service process identifiers.

A change in a listening port can result from legitimate service restarts, network configuration changes, software installations, or the activation of a new service. It can also occur during unauthorized activity. The alert alone cannot distinguish between these explanations.

## 5. Investigation Methodology

The investigation followed a structured workflow:

1. Alert identification.
2. Collection of supporting endpoint evidence.
3. Comparison of firewall policy with listening services.
4. Initial risk assessment.
5. Documentation of findings.
6. Identification of additional validation steps.

The investigation was performed using read-only inspection commands where possible. No destructive remediation was performed during the documented checks.

## 6. Evidence Collection and Analysis

### 6.1 Listening-Port Inventory

The following command was executed on the Ubuntu endpoint:

```bash
sudo ss -tulpen
```

The command displayed active TCP listeners and UDP sockets, their local addresses, and associated processes where available.

The following findings were recorded:

| Port | Service | Observed binding | Assessment |
|---|---|---|---|
| 22/TCP | SSH | `0.0.0.0` and `[::]` | Listening on all IPv4 and IPv6 interfaces |
| 53/TCP and UDP | System resolver | `127.0.0.53`, `127.0.0.54` | Local DNS resolver |
| 25/TCP | Postfix | `127.0.0.1`, `::1` | Local-only mail listener |
| 631/TCP | CUPS | `127.0.0.1`, `::1` | Local-only printing listener |
| 5353/UDP | Avahi | Wildcard IPv4 and IPv6 bindings | Network discovery service |
| 5432/TCP | PostgreSQL | `127.0.0.1` | Local-only database listener |
| 8000/TCP | Uvicorn / MlinziOps | `127.0.0.1` | Local-only application listener |
| 443/TCP | Tailscale | Tailscale interface | Overlay-network listener |
| 41641/UDP | Tailscale | Wildcard binding | Tailscale networking |
| 68/UDP | systemd-networkd | Host network interfaces | DHCP-related networking |

**Analysis:**

The listening-port inventory showed several services with plausible operational purposes. SSH supported remote administration, PostgreSQL provided a local database listener, and Uvicorn was associated with the MlinziOps application.

PostgreSQL and MlinziOps were bound to the loopback address. This reduces their direct exposure through other network interfaces, although access controls and application-level security must still be verified.

Avahi was listening on wildcard UDP addresses. Its necessity should be reviewed if network discovery is not required.

The output did not independently establish which configuration change triggered Rule 533. The differences between the previous and current snapshots require further correlation with service and authentication logs.

### 6.2 Firewall Configuration Review

The following command was executed:

```bash
sudo ufw status verbose
```

The observed firewall configuration was:

```text
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)

22/tcp                     ALLOW IN    Anywhere
11434/tcp                  ALLOW IN    192.168.187.0/24
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)
80/tcp (v6)                ALLOW IN    Anywhere (v6)
443/tcp (v6)               ALLOW IN    Anywhere (v6)
```

**Analysis:**

The firewall was active and configured to deny incoming traffic by default, with explicit rules allowing selected ports.

The SSH rules permitted incoming TCP connections from any source at the firewall-policy level for both IPv4 and IPv6. This increases potential exposure if the host is reachable from untrusted networks.

HTTP and HTTPS were also permitted by UFW. However, a permitted firewall port does not necessarily have an application listening on it.

Ollama traffic on port 11434 was permitted from the specified private IPv4 subnet. The inspection performed during this investigation did not show a TCP listener on that port.

The effective exposure of each service depends on routing, interface accessibility, other network controls, and the actual application configuration.

### 6.3 Service Status Verification

The following command was executed:

```bash
systemctl is-active avahi-daemon cups postfix
```

The observed result was:

```text
active
active
active
```

**Analysis:**

All three services were active at the time of verification.

Their active status does not indicate malicious activity. However, unnecessary services can increase the attack surface of a server.

The recommended next step is to determine whether network discovery, printing, and local mail functionality are required for the intended lab configuration before disabling anything.

### 6.4 Focused Listener Verification

The following command was executed:

```bash
sudo ss -lntp | grep -E ':(22|80|443|11434)\b'
```

The results showed:

- SSH listening on IPv4 and IPv6 wildcard addresses on port 22.
- Tailscale listening on port 443 through its overlay interface.
- No TCP listener matching port 80 in the displayed results.
- No TCP listener matching port 11434 in the displayed results.

**Analysis:**

The results demonstrated the importance of correlating firewall policy with live host state. A firewall rule permitting a connection does not prove that a corresponding application is listening.

The TCP listener on port 443 belonged to Tailscale in this snapshot. It should not be interpreted as evidence that an ordinary public HTTPS web server was running.

## 7. Findings and Risk Assessment

### Finding 1: Listening-port inventory changed

**Severity:** Wazuh Rule 533 — Level 7  
**Status:** Investigated; cause not conclusively established

Wazuh detected a change in the endpoint's listening-port inventory.

The current snapshot contained listeners associated with expected operating-system and lab services. The available evidence did not establish an unauthorized service or confirm malicious activity.

**Recommended action:** Correlate future port-change alerts with system logs, service restarts, package installations, and administrative activity.

### Finding 2: SSH permitted from any source

**Priority:** High hardening priority  
**Status:** Configuration review recommended

SSH was listening on all IPv4 and IPv6 interfaces. UFW permitted inbound SSH from any source.

This configuration can expose the administrative service to untrusted networks when routing permits access.

**Recommended action:** Restrict SSH to trusted source addresses or a dedicated management network where practical. Review SSH authentication settings and authentication logs before changing access rules.

### Finding 3: Local application and database listeners

**Priority:** Informational  
**Status:** No direct external binding observed

MlinziOps was listening on `127.0.0.1:8000`, and PostgreSQL was listening on `127.0.0.1:5432`.

These bindings limit direct network access through other interfaces. This is a positive exposure-reduction measure, but it does not replace authentication, authorization, secure configuration, or application testing.

**Recommended action:** Preserve loopback-only bindings unless remote access is explicitly required and can be appropriately secured.

### Finding 4: Active ancillary services

**Priority:** Low; review for necessity  
**Status:** Further validation recommended

Avahi, CUPS, and Postfix were active. Avahi had wildcard UDP listeners, while CUPS and Postfix had local-only TCP listeners.

**Recommended action:** Confirm operational requirements and disable unused services through a controlled change process.

### Finding 5: Firewall permits web traffic without a matching general web listener in the snapshot

**Priority:** Low; configuration hygiene  
**Status:** Review recommended

UFW permitted TCP ports 80 and 443, but the listener inspection did not identify a general web server bound to those ports. The observed port 443 listener was associated with Tailscale.

**Recommended action:** Confirm whether the firewall rules are required for planned services. Remove obsolete rules only after validating dependencies and access requirements.

## 8. Recommended Next Steps

The following actions are recommended in order of priority:

1. **Review SSH authentication:** Inspect effective SSH configuration and recent successful and failed authentication events.
2. **Validate network exposure:** Confirm whether SSH is reachable from untrusted networks and whether the firewall rules align with the intended access model.
3. **Correlate the port-change event:** Review service and system logs around the alert timestamp to determine whether the changes resulted from routine operations.
4. **Review unnecessary services:** Establish whether Avahi, CUPS, and Postfix are required.
5. **Review firewall rules:** Retain only the inbound access rules needed by the lab.
6. **Continue monitoring:** Check whether similar port-change alerts recur and whether they correlate with unexpected processes or authentication activity.

Any SSH or firewall changes should be planned carefully to preserve legitimate administrative access and prevent accidental lockout.

## 9. Suggested Validation Commands

The following commands can support the next phase of investigation.

### Review effective SSH security settings

```bash
sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries)'
```

This reports selected effective SSH settings. Their security implications depend on the complete SSH configuration and access requirements.

### Review recent SSH authentication events

```bash
sudo journalctl --since "24 hours ago" --no-pager \
  | grep -E 'sshd.*(Failed password|Invalid user|Accepted (publickey|password))' \
  | tail -n 30
```

This searches available system journal entries for selected SSH authentication messages. The result depends on the host's logging configuration and retention period.

### Review current listeners

```bash
sudo ss -tulpen
```

This supports comparison of the current endpoint state with future Wazuh alerts.

### Review firewall policy

```bash
sudo ufw status verbose
```

This displays the current UFW policy and helps verify the effects of approved firewall changes.

## 10. Investigation Limitations

This investigation was based on a Wazuh alert, endpoint listener snapshots, firewall configuration, and service-status checks.

The following activities were not established as completed in the evidence documented here:

- A complete review of successful and failed SSH authentication events.
- A controlled external reachability test from an independent network.
- A definitive identification of the process or configuration change responsible for Rule 533.
- A full review of application logs, process execution history, and system integrity.
- Confirmation that every active service was necessary for the lab.

Consequently, this report does not claim that the endpoint was compromised or that all possible attack paths were excluded.

## 11. Conclusion

The investigation demonstrated a structured approach to analysing a Wazuh listening-port change alert by correlating central security monitoring with host-level evidence and firewall policy.

The endpoint had an active UFW firewall with a default-deny incoming policy. The review also identified broadly permitted SSH access, several local-only application and database listeners, and active ancillary services that warrant a necessity review.

No confirmed compromise was established by the evidence examined. The appropriate disposition is to continue validation, review SSH exposure, and correlate future alerts with relevant system activity.

This exercise demonstrates practical SOC skills in alert triage, Linux host inspection, firewall analysis, evidence-based risk assessment, and investigation documentation.

## 12. Skills Demonstrated

- Wazuh alert triage and interpretation.
- Linux TCP and UDP listener inspection.
- UFW firewall policy analysis.
- Service identification and exposure assessment.
- Correlation of endpoint evidence with SIEM alerts.
- Risk-based prioritisation and defensive recommendations.
- Documentation of investigation scope and limitations.

## 13. References

1. Wazuh Documentation. *Wazuh documentation*. https://documentation.wazuh.com/current/
2. Ubuntu Documentation. *Ubuntu Server documentation*. https://documentation.ubuntu.com/server/
3. Linux Manual Pages. *ss(8) — another utility to investigate sockets*. https://man7.org/linux/man-pages/man8/ss.8.html
4. Linux Manual Pages. *systemctl(1) — control the systemd system and service manager*. https://www.freedesktop.org/software/systemd/man/latest/systemctl.html
5. Ubuntu Manual Pages. *ufw(8) — program for managing a netfilter firewall*. https://manpages.ubuntu.com/manpages/

---

**Report status:** Initial investigation documented. Additional authentication and exposure validation is recommended before closing the case as benign.

**Portfolio note:** This report documents an educational lab investigation. All conclusions are limited to the evidence collected and commands executed during the exercise.
