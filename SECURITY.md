# Security

PDF files can contain active content, embedded files, malformed objects, and intentionally adversarial structures. PDF Hexmator performs lexical and structural triage and does not intentionally execute PDF content.

## Reporting security issues

Do not include sensitive evidence or personal data in a public issue. Provide a minimal synthetic reproducer whenever possible.

## External validators

`-ExternalValidation` launches locally installed third-party tools against the supplied PDF. Review and trust those tools independently before enabling this option in sensitive environments.
