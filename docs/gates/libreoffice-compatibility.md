# LibreOffice DOCX compatibility evidence

Verified on 2026-07-15 on Debian 13 ARM64 with LibreOffice 25.2.3.2. The appliance dependency was
installed without recommended desktop packages:

```text
sudo apt-get install -y --no-install-recommends libreoffice-writer-nogui
```

The initial check exposed a compatibility defect: ElementTree emitted namespace-equivalent `ns0`
prefixes on the three OPC container roots, which LibreOffice rejected before opening the document.
The renderer now emits the required default namespace on `[Content_Types].xml`, `_rels/.rels`, and
`word/_rels/document.xml.rels`; a package bisect confirmed no document, section, or SVG change was
needed.

The production report compatibility test generates a sanitized, representative DOCX through
`generate_reports`, validates the bounded ZIP/XML package and registered-secret scan, and confirms
that it has no external relationships. It then starts LibreOffice headlessly with a temporary
`UserInstallation` URI, converts the DOCX through `writer_pdf_Export`, verifies a single PDF header,
round-trips it through the Office Open XML Text exporter, and reopens the resulting DOCX through a
second PDF conversion. Each conversion has a distinct isolated profile. All reports, converted
files, and profile data stay in the pytest temporary directory and are deleted after the test.

Reproduce the focused check with:

```text
python -m pytest -o addopts='' \
  tests/test_reporting.py::test_libreoffice_can_open_generated_docx_when_available
```

No GUI package, service, live endpoint, customer data, credential, or external upload is involved.
