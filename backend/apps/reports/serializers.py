from rest_framework import serializers

from .models import Report


class ReportSerializer(serializers.ModelSerializer):
    project_name = serializers.CharField(source="project.name", read_only=True)

    class Meta:
        model = Report
        fields = ["id", "project", "project_name", "scan", "report_type", "status", "created_at"]
        read_only_fields = fields


class ReportGenerateSerializer(serializers.Serializer):
    report_type = serializers.ChoiceField(choices=["json", "pdf"], default="json")
