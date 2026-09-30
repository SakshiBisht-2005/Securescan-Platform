"""Compare two scans including code findings and secrets."""
from apps.vulnerabilities.serializers import FindingSerializer, SecretFindingSerializer
from scanner_engine.deduplicator import diff_findings


def path_in_scope(file_path: str, scope_path: str) -> bool:
    if not scope_path:
        return True
    path = (file_path or "").replace("\\", "/").lstrip("./")
    scope = scope_path.replace("\\", "/").lstrip("./").rstrip("/")
    if not scope:
        return True
    return path == scope or path.startswith(scope + "/")


def _fp_map(scan, scope_path=""):
    mapping = {}
    for finding in scan.findings.all():
        if path_in_scope(finding.file_path, scope_path):
            mapping[f"f:{finding.fingerprint}"] = ("finding", finding)
    for secret in scan.secret_findings.all():
        if path_in_scope(secret.file_path, scope_path):
            mapping[f"s:{secret.fingerprint}"] = ("secret", secret)
    return mapping


def _serialize(kind, obj):
    if kind == "finding":
        data = FindingSerializer(obj).data
        data["kind"] = "finding"
        return data
    data = SecretFindingSerializer(obj).data
    data["kind"] = "secret"
    data["title"] = obj.secret_type
    data["line_start"] = obj.line_number
    data["scanner"] = "secrets"
    data["category"] = "secrets"
    return data


def compare_scans(scan_a, scan_b, scope_path=""):
    map_a = _fp_map(scan_a, scope_path)
    map_b = _fp_map(scan_b, scope_path)
    diff = diff_findings(set(map_a), set(map_b))

    def collect(keys, source):
        rows = []
        for key in keys:
            item = source.get(key)
            if item:
                rows.append(_serialize(*item))
        rows.sort(key=lambda r: (r.get("severity") or "", r.get("file_path") or ""))
        return rows[:200]

    new_rows = collect(diff["new"], map_b)
    resolved_rows = collect(diff["resolved"], map_a)
    still_open = collect(diff["unchanged"], map_b)

    return {
        "new_findings": new_rows,
        "resolved_findings": resolved_rows,
        "still_open_findings": still_open,
        "new_count": len(diff["new"]),
        "resolved_count": len(diff["resolved"]),
        "still_open_count": len(diff["unchanged"]),
        "unchanged_count": len(diff["unchanged"]),
        "security_score_delta": (scan_b.security_score or 0) - (scan_a.security_score or 0),
        "scope_path": scope_path or "",
    }
