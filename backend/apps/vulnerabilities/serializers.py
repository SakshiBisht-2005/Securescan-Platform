from rest_framework import serializers

from .models import Dependency, Finding, SecretFinding


class FindingSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name", read_only=True)

    class Meta:
        model = Finding
        fields = [
            "id", "scan", "project", "project_name", "scanner", "rule_id", "title", "description",
            "severity", "scanner_severity", "confidence", "category", "cwe", "owasp_category",
            "file_path", "line_start", "line_end", "column_start", "column_end", "code_snippet",
            "remediation", "references", "fingerprint", "status", "status_changed_by", "status_changed_at",
            "first_detected_at", "last_detected_at", "created_at",
        ]
        read_only_fields = [f for f in fields if f not in ("status",)]


class FindingStatusUpdateSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=["open", "resolved", "ignored", "false_positive"])
    note = serializers.CharField(required=False, allow_blank=True)


class DependencySerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name", read_only=True)

    class Meta:
        model = Dependency
        fields = [
            "id", "project", "project_name", "scan", "package_name", "version", "ecosystem",
            "manifest_file", "vulnerability_id", "severity", "description", "fixed_version",
            "created_at",
        ]
        read_only_fields = fields


class SecretFindingSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name", read_only=True)

    class Meta:
        model = SecretFinding
        fields = ["id", "project", "project_name", "scan", "secret_type", "file_path",
                  "line_number", "masked_value", "severity", "status", "created_at"]
        read_only_fields = [f for f in fields if f not in ("status",)]
