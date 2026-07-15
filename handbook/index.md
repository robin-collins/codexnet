---
title: CodexNet Field Handbook
description: Practical onsite guide for deploying and operating the CodexNet network discovery appliance.
---

<div class="hero" markdown>

# CodexNet Field Handbook

Deploy, operate, and close out an authorised network discovery engagement from a Raspberry Pi.

[Start a new site](getting-started/new-site.md){ .md-button .md-button--primary }
[Run the onsite workflow](operations/runbook.md){ .md-button }

</div>

This handbook is written for the technician holding the appliance onsite. It covers preparation,
safe connection, site configuration, credential profiles, passive and active collection, report
production, troubleshooting, backup, and customer-data closeout.

!!! danger "Authorisation is the first control"
    Connect or collect only on a network explicitly listed in the written assessment scope.
    CodexNet does not make an unauthorised target safe. Stop if the connected subnet, customer,
    change window, or approved targets do not match the work order.

## The normal field sequence

1. Review the [pre-deployment checklist](getting-started/pre-deployment.md).
2. Connect the Pi to the approved customer-facing Ethernet segment.
3. Follow [new-site setup](getting-started/new-site.md) and prove the live subnet without scanning.
4. Configure only the collectors and concrete targets approved for this engagement.
5. Run the [onsite workflow](operations/runbook.md), beginning with passive observation.
6. Generate, validate, and visually review the Word report.
7. Upload the DOCX manually through the authorised customer platform.
8. Back up or remove customer data according to the engagement retention decision.

## Safety model at a glance

| Activity | Default | Technician action |
|---|---|---|
| Passive LLDP/CDP, mDNS, DHCP, ARP and neighbour observation | Enabled service | Confirm service health |
| Completed nmap XML import | Read-only timer | Confirm import health |
| SNMP, UniFi, AD and SSH collection | Disabled | Configure approved targets and credentials |
| Active nmap execution | Never scheduled by CodexNet | Confirm scope and invoke explicitly |
| Report upload | Not implemented | Validate, review, then upload manually |
| Scanopy integration | Separate service only | Check health; never access its private database |

## Need an answer quickly?

- Appliance unhealthy: [Troubleshooting](operations/troubleshooting.md)
- Collector setup: [Collectors](operations/collectors.md)
- Report handoff: [Reports and handoff](operations/reporting.md)
- Exact syntax: [Command reference](reference/commands.md)
- Data locations: [Files and services](reference/files-services.md)
