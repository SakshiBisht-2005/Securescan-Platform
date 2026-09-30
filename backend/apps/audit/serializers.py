from rest_framework import serializers

from .models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True, default="")

    class Meta:
        model = AuditLog
        fields = ["id", "user", "username", "action", "object_type", "object_id", "ip_address", "timestamp", "metadata"]
        read_only_fields = fields
