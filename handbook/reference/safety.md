# Safety boundaries

These controls are release requirements, not optional recommendations.

## Always

- Operate only with explicit written authorisation.
- Prefer passive collection and least-privilege read-only accounts.
- Require concrete approved targets, timeouts, bounded retries, and concurrency.
- Keep TLS verification and SSH host-key checking enabled.
- Use SNMPv3 unless an approved legacy exception requires v2c.
- Keep credentials out of source, YAML, commands, logs, databases, reports, and tickets.
- Preserve source, time, confidence, conflicts, and limitations in customer documentation.
- Validate and visually review the exact DOCX before manual upload.

## Never

- Exploit vulnerabilities or perform denial-of-service testing.
- Dump credentials, crack passwords, spray/guess accounts or communities, or use defaults.
- Kerberoast, AS-REP roast, export tickets, or collect AD attack paths.
- Enter network-device configuration mode or run write commands.
- Store unrestricted packet captures.
- Disable TLS globally or accept unknown SSH host keys for convenience.
- Automatically upload customer data to IT Glue, Datto RMM, Autotask, or another cloud service.
- Access Scanopy's private database.
- Create a competing scheduled nmap scan.
- Delete broad directories to solve disk pressure or close an engagement.

## Stop-work triggers

Stop collection and escalate when scope is ambiguous, the connected subnet differs from the work
order, a target control refuses the operation, a credential may have leaked, protected state changed
unexpectedly, or safe read-only operation cannot be proven.
