# Specification Refinement Notes

Status: interview paused; approved decisions recorded for later incorporation into `SPEC.md`.

Recorded: 2026-07-16 (Australia/Adelaide)

These notes are an interview checkpoint, not a replacement for `SPEC.md`. Requirements below were approved by the appliance owner. Open questions remain provisional and must not be implemented as decided requirements until answered. When refinement resumes, continue with the open questions rather than repeating settled topics.

## Interview response convention

- Unless the owner specifies a variation, the recommended answer to each question is approved.
- `approved` approves every recommendation in the current round.
- A numbered response overrides only that numbered recommendation; all other recommendations in the round are approved.
- Do not use this convention to infer approval for a material scope expansion that was not presented clearly in an interview question.

## Approved decisions

### Deployment identity and grouping

- Customer work is grouped into named deployments.
- Each visit has a distinct identity comprising customer, site, and its dated start time, so repeat visits never share a deployment.
- Store an immutable internal UUID in addition to the human-readable deployment key.
- Generate a human-readable key from customer, site, and local start timestamp, including seconds, for example `CompanyName-Adelaide-Office-20260716-143025`.
- Store the immutable start timestamp with its UTC offset. Crossing midnight does not rename a deployment.
- Refuse deployment creation when the system clock is unsynchronized or has moved backwards sufficiently to make evidence timing or identity unreliable.
- Accept either the immutable UUID or human-readable key when selecting a deployment.
- Permit many deployments to remain stored, but allow only one active deployment to collect data at a time.
- A closed deployment is immutable and cannot resume collection. A later visit always requires a new dated deployment.
- A closed deployment may be used to regenerate a report from its retained snapshot without reopening it.

### Deployment creation and customer/site input

- Provide an interactive deployment creation workflow as the normal onsite path:

  ```bash
  field-discovery new-deployment
  ```

- Prompt interactively for customer and site names without echoing the entered details.
- Also support explicit `--customer` and `--site` options for deliberate automation, while documenting that these values can remain in shell history and process arguments.

### Initial network detection and approval

- On deployment creation, identify the eligible IPv4 default route and derive the collection CIDR from the global IPv4 address and prefix assigned to that route's interface. The gateway address alone is not treated as a source of prefix length.
- Automatically approve the initially detected directly connected CIDR without an interactive confirmation.
- Record the selected interface, interface address, gateway, derived CIDR, route information, timestamp, and approval source in deployment audit history.
- Exclude Docker, Tailscale, Wi-Fi, loopback, and other configured interface classes unless the operator selects one explicitly.
- If multiple eligible IPv4 default routes exist, select the lowest-metric route.
- If eligible routes are tied at equal priority, fail deployment creation and require an explicit interface.
- If no eligible default route, gateway, or global IPv4 address is available, fail deployment creation. Permit the operator to supply both an interface and CIDR explicitly.
- An explicitly supplied CIDR must be directly connected through the selected interface and pass the configured prefix/range safeguards. Routed or non-local CIDRs remain outside initial scope.
- Provide a manual correction operation for an incorrectly detected network. A correction must pause collection, validate the replacement directly connected CIDR and interface, record an audit event, and resume only after the change succeeds.

### Network changes during collection

- If the default route, selected interface address, gateway, or derived CIDR changes during an active deployment, immediately pause all collection, including passive collection.
- Allow already-started transactional database writes to finish safely and mark incomplete collector runs accurately.
- Record the detected network change without retaining packet content merely for change detection.
- Require an explicit network-change acceptance or manual network correction before collection resumes.
- Never silently add a newly observed subnet to the deployment's approved scope.

### Nmap scheduling

- Treat an nmap schedule as an external appliance prerequisite.
- Do not create, replace, or repair an nmap cron job or systemd timer automatically.
- `field-discovery doctor` must report clearly when the expected external nmap schedule is absent.
- Existing safety rules remain unchanged: `scan nmap` is an explicit operator action, and CodexNet must not introduce a competing automatic active-scan schedule.

### Open-deployment retention

- Retain all collected data for an open deployment until closeout, subject to disk-safety suspension.
- Do not prune open-deployment raw artifacts through ordinary age-based retention.
- Begin configured post-engagement retention only after closeout.
- Never delete open-deployment data automatically to recover disk space.

### Closeout workflow

- Provide a deployment closeout command that performs an all-or-nothing logical workflow:
  1. stop and drain collectors;
  2. finish or accurately mark incomplete runs;
  3. import stable pending nmap XML;
  4. snapshot the database and all deployment artifacts;
  5. generate and validate reports;
  6. build and verify the backup archive; and
  7. mark the deployment closed and non-collectable.
- If any closeout step fails, leave the deployment open and resumable. Never label a partial archive as a successful closeout.
- Create an unencrypted ZIP archive because the operator will handle it through an approved secure process.
- Store closeout archives under `/var/lib/field-discovery/backups/<deployment-key>/` with directory mode `0700` and archive mode `0600`.
- Create the archive atomically, then verify ZIP integrity, the database integrity check, manifest checksums, and DOCX validation before declaring success.
- Include all deployment data in the archive:
  - validated DOCX and JSON reports;
  - a consistent SQLite database snapshot;
  - all raw collector artifacts;
  - any diagnostic packet capture that the operator explicitly created;
  - rendered diagrams and their source files;
  - sanitized operational logs attributable to the deployment;
  - a non-secret configuration snapshot containing secret references but not values;
  - coverage and error summaries; and
  - a manifest containing checksums plus application and schema versions.
- “All data” explicitly excludes credentials and reusable secrets, including passwords, tokens, authentication cookies, SNMP communities, and secret values. Existing secret-handling prohibitions remain authoritative.
- Do not automatically delete closeout archives.

### Purge and backup deletion

- Keep live deployment data after closeout until the operator runs an explicit purge command.
- `purge-deployment` removes working database records and artifacts but retains the verified closeout archive.
- Refuse ordinary purge unless a valid closeout archive exists and passes verification.
- Provide an explicitly audited emergency override, requiring the exact deployment key, for purging without a valid backup.
- Deleting the retained archive is a separate explicit operation with confirmation and an audit record.

### Resource limits

- Combined CodexNet service memory ceiling: 1.5 GB.
- Passive service memory ceiling: 512 MB.
- Collector scheduler memory ceiling: 768 MB.
- Report generation memory ceiling: 1 GB, with report generation isolated from concurrent collectors.
- Maximum of 10 simultaneous network operations and no more than 3 operations against one target.
- Reduce scheduled collector work after sustained 80% CPU use and pause scheduled collectors at 90% CPU use.
- Do not interrupt database commits or closeout verification merely because CPU utilization is high.

### Low-disk degradation

- Warn below 20% free space or 10 GB free, whichever threshold is reached first.
- Pause raw-artifact creation and scheduled collectors below 15% free or 5 GB free.
- Pause all collection, including passive structured observations and nmap imports, below 5% free or 1 GB free.
- Keep status, diagnostics, closeout, backup, and purge operations available where sufficient space exists for the requested operation.
- Never delete open-deployment data automatically.

### Passive overload behavior

- Use bounded backpressure.
- If the capture source overruns, record aggregate loss counters and disclose incomplete coverage.
- Prioritize identity/topology evidence over repetitive ARP and mDNS refresh observations.
- Never silently claim complete collection after event loss.

### Backup restoration

- Provide `field-discovery restore-backup <archive.zip>`.
- Before restoration, validate restrictive permissions, ZIP paths, manifest checksums, schema compatibility, database integrity, and required free disk space.
- Restore the deployment as closed and immutable.
- Refuse deployment UUID/key collisions unless the existing and archived deployment are identical.

### Authorization responsibility

- Network authorization is arranged externally by the appliance operator through 1Solution's MSP processes.
- CodexNet does not prompt for authorization attestation and does not store an operator name, job/ticket reference, or authorization document.
- The product documentation must still state that CodexNet may be used only on explicitly authorized customer networks.

### Reboot and interruption recovery

- Automatically resume the single active deployment after reboot only when the selected interface, gateway, and derived CIDR still match its approved network identity.
- Before resuming, mark interrupted collector runs incomplete rather than treating them as successful.
- If the network identity differs or cannot be verified, keep all collection paused until the operator explicitly accepts or corrects the network.

### Single-active-deployment enforcement

- Enforce the single-active-deployment rule with transactional database state and a process lock.
- If another deployment is active, starting a deployment must fail with instructions for closing or pausing the active deployment.
- Never switch customer or deployment context implicitly.

### Audit history

- Retain an append-only, hash-chained audit trail for deployment creation, network changes, collector lifecycle, closeout, restore, purge, emergency overrides, and backup deletion.
- Do not record an authorization attestation because authorization is managed outside CodexNet.
- Include the complete audit trail in the closeout backup and a concise activity summary in the report.
- Exclude secrets and repetitive low-level operational events from the audit trail.

### Credential failure isolation

- After a bounded number of failed authentication attempts, disable only the affected credential profile or collector.
- Continue all unrelated collection when a credential profile is disabled.
- Report credential failures clearly through `status` without revealing secret values.
- Resume authentication attempts only after the referenced secret changes or the operator explicitly resets the failure state.

### Offline timekeeping

- Require a plausible synchronized clock when deployment creation can verify synchronization through NTP or another configured time source.
- When operating offline, allow the operator to confirm a manually set clock after displaying a warning.
- Record monotonic durations alongside wall-clock timestamps so later clock corrections do not corrupt run durations or evidence ordering.

### Report identity and revision

- Identify reports with customer, site, immutable deployment start time, report generation time, deployment UUID, document revision, application version, and schema version.
- Regenerating a report for a closed deployment increments the document revision.
- Report regeneration does not change deployment identity or original assessment dates.

### Upgrades and migrations

- Before an upgrade, create and verify a database backup.
- Apply forward-only numbered migrations before starting newer application services.
- If migration or upgrade validation fails, restore the pre-upgrade version and leave services stopped with actionable diagnostics.
- Never partially run newer application code against an older schema.
- Existing closed-deployment backup archives remain immutable across upgrades.

## Open questions for the next interview round

Continue with collector targeting, credential assignment, treatment of unknowns, and backup portability.

## Resume point

Resume the `refine-spec` interview with collector targeting, credential assignment, treatment of unknowns, and backup portability. Continue afterward with security/privacy, report usability, dependency failure, and migration compatibility. Update `SPEC.md` and add its formal Decisions Log only when the interview is complete or the owner explicitly requests an intermediate specification revision.
