from rest_framework import serializers

from .access import project_role_for
from .models import Project, ProjectFile, ProjectInvite, ProjectMembership


class ProjectSerializer(serializers.ModelSerializer):
    owner_username = serializers.CharField(source="owner.username", read_only=True)
    latest_scan_status = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = [
            "id", "owner", "owner_username", "name", "description", "repository_url",
            "default_branch", "language", "status", "exclusion_patterns",
            "created_at", "updated_at", "latest_scan_status",
            "weekly_scan_enabled", "has_ci_token", "ci_token_prefix",
            "my_role", "member_count",
        ]
        read_only_fields = [
            "id", "owner", "created_at", "updated_at", "has_ci_token", "ci_token_prefix",
            "my_role", "member_count",
        ]

    has_ci_token = serializers.SerializerMethodField()
    my_role = serializers.SerializerMethodField()
    member_count = serializers.SerializerMethodField()

    def get_has_ci_token(self, obj):
        return bool(obj.ci_token_hash)

    def get_my_role(self, obj):
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return None
        return project_role_for(request.user, obj)

    def get_member_count(self, obj):
        extra = obj.memberships.exclude(user_id=obj.owner_id).count()
        return extra + 1

    def get_latest_scan_status(self, obj):
        latest = obj.scans.order_by("-created_at").first()
        return latest.status if latest else None

    def validate_name(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("Project name cannot be empty.")
        return value

    def update(self, instance, validated_data):
        if "weekly_scan_enabled" not in getattr(self, "initial_data", {}):
            validated_data.pop("weekly_scan_enabled", None)
        return super().update(instance, validated_data)


class ProjectFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProjectFile
        fields = ["id", "path", "filename", "language", "size", "hash", "is_binary", "created_at"]
        read_only_fields = fields


class ProjectFileContentSerializer(serializers.Serializer):
    """Used by the code-editor API to read/write a single file's content."""

    path = serializers.CharField()
    content = serializers.CharField(allow_blank=True, required=False)


class ProjectMembershipSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    email = serializers.EmailField(source="user.email", read_only=True)

    class Meta:
        model = ProjectMembership
        fields = ["id", "user", "username", "email", "role", "created_at"]
        read_only_fields = fields


class InviteMemberSerializer(serializers.Serializer):
    email = serializers.EmailField()
    role = serializers.ChoiceField(
        choices=[c for c in ProjectMembership.ROLE_CHOICES if c[0] != ProjectMembership.ROLE_OWNER],
        default=ProjectMembership.ROLE_DEVELOPER,
    )


class ProjectInviteSerializer(serializers.ModelSerializer):
    invited_by_username = serializers.CharField(source="invited_by.username", read_only=True)
    project_name = serializers.CharField(source="project.name", read_only=True)

    class Meta:
        model = ProjectInvite
        fields = ["id", "project", "email", "role", "accepted", "created_at", "expires_at", "invited_by_username", "project_name"]
        read_only_fields = fields
