# Reports and handoff

CodexNet produces a self-contained Word DOCX and a deterministic JSON companion. Only the validated
DOCX is intended for manual customer-platform upload.

## Generate

Confirm report metadata in configuration, then run:

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --json --config /etc/field-discovery/config.yaml \
  report generate --format docx
```

The output directory defaults to `/var/lib/field-discovery/reports`. The production filename is
`Customer-Site-Network-Discovery-YYYYMMDD.docx` with unsafe filename characters normalized.

## Validate the exact file

```bash
REPORT=/var/lib/field-discovery/reports/Customer-Site-Network-Discovery-YYYYMMDD.docx
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml report validate "$REPORT"
sha256sum "$REPORT"
```

Validation checks ZIP/XML integrity, required sections and metadata, relationships, embedded images,
external resources, production filename, and secret/prohibited-content patterns. A failure means the
file is not upload-ready.

## Visual review

Open a copy in current Microsoft Word or LibreOffice and:

- update the table of contents;
- confirm customer, site, author, version, and confidentiality labels;
- inspect page breaks, wide tables, diagrams, and repeated headings;
- review collection coverage, failed/partial collectors, age, conflicts, assumptions, and limitations;
- confirm no internal JSON, credentials, or unexpected customer data appear; and
- save, revalidate, and recalculate the checksum if the document changes.

## Manual platform handoff

Use the normal authenticated attachment/document UI in IT Glue, Datto RMM, or Autotask. Select the
correct customer/site, apply the intended access controls, upload the validated DOCX, and record the
checksum and upload time in the authorised engagement record.

!!! warning "No automatic upload"
    Do not give CodexNet platform credentials or add an upload script. Do not upload the SQLite
    database, raw artifacts, internal JSON companion, journals, or nmap result tree.

After the recipient confirms access, retain or securely remove local copies according to the
engagement plan.
