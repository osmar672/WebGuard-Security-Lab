"""Small dependency-free PDF exporter for readable security summaries."""
from __future__ import annotations

import json
import re
import unicodedata
from datetime import UTC, datetime
from typing import Any


def _ascii(value: Any) -> str:
    text = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", text)
    return text


def _pdf_literal(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf_report(document: dict[str, Any]) -> bytes:
    """Return a basic multi-page, printable PDF for audit/workspace report documents."""
    lines = [
        "WebGuard Security Lab - Report",
        f"Generated: {datetime.now(UTC).isoformat()}",
        f"Type: {document.get('report_type', 'webguard_report')}",
        f"Source ID: {document.get('audit_id') or document.get('scan_id') or 'n/a'}",
        f"State: {document.get('state', 'n/a')}",
        "",
    ]
    target = document.get("target")
    if isinstance(target, dict):
        lines.extend([f"Target: {target.get('name', '')} ({target.get('hostname', '')})", ""])
    results = document.get("results")
    if isinstance(results, dict):
        summary = {key: value for key, value in results.items() if key != "sbom_document"}
        lines.extend(["Summary:", json.dumps(summary, ensure_ascii=True, indent=2)[:12000], ""])
    findings = document.get("findings") or []
    lines.append(f"Findings: {len(findings)}")
    lines.append("")
    for index, finding in enumerate(findings[:2000], start=1):
        if not isinstance(finding, dict):
            continue
        lines.append(f"{index}. [{str(finding.get('severity', 'info')).upper()}] {finding.get('title', 'Finding')}")
        if finding.get("url"):
            lines.append(f"   URL: {finding['url']}")
        if finding.get("description"):
            description = str(finding["description"]).replace("\r", " ").replace("\n", " ")
            lines.append(f"   Details: {description[:1000]}")
        lines.append("")
    lines.append("Note: Automated results require validation. A finding missing in a later run is not proof of remediation.")

    wrapped: list[str] = []
    for line in lines:
        ascii_line = _ascii(line)
        if not ascii_line:
            wrapped.append("")
            continue
        while len(ascii_line) > 95:
            split_at = ascii_line.rfind(" ", 0, 95)
            if split_at < 20:
                split_at = 95
            wrapped.append(ascii_line[:split_at])
            ascii_line = ascii_line[split_at:].lstrip()
        wrapped.append(ascii_line)
    page_lines = [wrapped[i:i + 48] for i in range(0, max(1, len(wrapped)), 48)]

    objects: list[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    page_refs = " ".join(f"{3 + index * 2} 0 R" for index in range(len(page_lines)))
    objects.append(f"<< /Type /Pages /Kids [{page_refs}] /Count {len(page_lines)} >>".encode("ascii"))
    for index, group in enumerate(page_lines):
        page_object_id = 3 + index * 2
        content_object_id = page_object_id + 1
        commands = ["BT", "/F1 10 Tf", "50 790 Td", "14 TL"]
        for line in group:
            commands.append(f"({_pdf_literal(line)}) Tj")
            commands.append("T*")
        commands.append("ET")
        stream = "\n".join(commands).encode("ascii", errors="replace")
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 {3 + 2 * len(page_lines)} 0 R >> >> /Contents {content_object_id} 0 R >>".encode("ascii")
        )
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    output = bytearray(b"%PDF-1.4\n%WebGuard\n")
    offsets = [0]
    for object_id, data in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_id} 0 obj\n".encode("ascii"))
        output.extend(data)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
    return bytes(output)
