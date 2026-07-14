# Production Word reports

CodexNet generates a deterministic, self-contained DOCX plus matching normalized JSON. Before
`report generate`, configure explicit `report.customer_name`, `report.site_name`, and
`report.author` values. `report.company_name`, `report.document_version`, and
`report.confidentiality` control the remaining customer-facing metadata. These values are never
derived from a credential or secret provider.

The stable output name is
`Customer-Site-Network-Discovery-YYYYMMDD.docx` after filename sanitization. A second generation
for the same customer, site, and date refuses to overwrite the existing report.

## Document structure

The built-in renderer provides:

- a title page with customer, site, assessment dates, author, company, version, confidentiality,
  and generation timestamp;
- an updateable Word table-of-contents field and numbered Heading 1/Heading 2 styles;
- company/customer/site headers and confidentiality/page/total-page footers;
- repeating table header rows and non-splitting rows;
- landscape sections for wide infrastructure and inventory tables;
- embedded, bounded SVG diagrams for network topology, VLAN/subnet relationships, switch ports,
  UniFi topology, and Active Directory structure;
- executive summary, coverage, device/service inventory, switch-port/VLAN/neighbour, printer,
  UPS/environment, firmware-version, UniFi, AD, conflicts, data-quality, and limitations sections.

Diagram assets are generated from the already-redacted report model, embedded inside the DOCX,
and contain no external links. Large diagrams disclose omitted entry counts instead of creating an
unbounded image. Wide, empty, and representative large models are covered by semantic tests.

## Optional DOCX template

Set `report.template` to an absolute path to a self-contained `.docx` when company Word styles are
required. CodexNet imports only its `word/styles.xml` part, then ensures the required report and
numbered-heading styles exist. It does not copy template document content, macros, relationships,
or remote resources.

Templates are rejected when they are missing, symlinked, not regular DOCX files, oversized,
malformed, contain entity declarations, lack a styles part, or include an external relationship.
This deliberately narrow style-only contract keeps generated reports deterministic and
self-contained.

## Verification

The renderer tests inspect the unzipped package and prove the TOC, numbering, headers, footers,
page fields, repeating table headings, portrait/landscape sections, image relationships, embedded
assets, required report sections, metadata, template behavior, deterministic output, and absence
of external relationships. LibreOffice conversion is run headlessly when LibreOffice/soffice is
installed; otherwise that optional environment check is explicitly skipped. Final redaction and
corruption validation is completed under T601.
