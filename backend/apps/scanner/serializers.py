from rest_framework import serializers

from .models import Scan, ScannerRun


class ScannerRunSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScannerRun
        fields = ["scanner_name", "status", "findings_count", "duration_seconds", "started_at", "finished_at"]


class ScanSerializer(serializers.ModelSerializer):
    scanner_runs = ScannerRunSerializer(many=True, read_only=True)
    project_name = serializers.CharField(source="project.name", read_only=True)

    class Meta:
        model = Scan
        fields = [
            "id", "project", "project_name", "scan_type", "status", "progress_percent", "progress_stage",
            "enabled_scanners", "severity_threshold", "branch", "exclusions",
            "started_at", "completed_at", "duration_seconds",
            "total_files", "total_findings", "critical_count", "high_count", "medium_count",
            "low_count", "info_count", "security_score", "error_message",
            "triggered_by", "created_at", "scanner_runs", "trigger_source", "git_sha",
            "scope_path",
        ]
        read_only_fields = [f for f in fields if f not in ("severity_threshold",)]


class ScanCreateSerializer(serializers.Serializer):
    scan_type = serializers.ChoiceField(choices=["full", "sast", "sca", "secrets", "iac", "container"], default="full")
    enable_sast = serializers.BooleanField(default=True)
    enable_sca = serializers.BooleanField(default=True)
    enable_secrets = serializers.BooleanField(default=True)
    enable_iac = serializers.BooleanField(default=True)
    enable_container = serializers.BooleanField(default=True)
    branch = serializers.CharField(required=False, allow_blank=True, default="")
    exclusions = serializers.ListField(child=serializers.CharField(), required=False, default=list)
    severity_threshold = serializers.ChoiceField(
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], required=False, allow_blank=True, default=""
    )
    generate_report = serializers.BooleanField(default=True)
    scope_path = serializers.CharField(required=False, allow_blank=True, default="")

    def to_enabled_scanners(self):
        data = self.validated_data
        return {
            "sast": data["enable_sast"], "sca": data["enable_sca"], "secrets": data["enable_secrets"],
            "iac": data["enable_iac"], "container": data["enable_container"],
        }
