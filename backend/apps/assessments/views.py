import json

from django.db import connection
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from common.exceptions import ValidationAppError

from . import analyzers
from .modes import MODE_MAP, MODES


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


class HealthView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        db_ok = True
        try:
            connection.ensure_connection()
        except Exception:  # noqa: BLE001
            db_ok = False
        payload = {"ok": db_ok, "service": "securescan"}
        return ok(payload)


class AssessmentCatalogView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return ok(
            {
                "modes": MODES,
                "notice": (
                    "Live checks only run against public URLs you confirm you operate. "
                    "This is not internet-wide scanning or exploit testing."
                ),
            }
        )


class AssessmentRunView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "assessments"

    def post(self, request):
        mode = (request.data.get("mode") or "").strip()
        meta = MODE_MAP.get(mode)
        if not meta:
            raise ValidationAppError("Unknown assessment mode.")
        confirm = request.data.get("confirm_owned")
        if isinstance(confirm, str):
            confirm = confirm.lower() in ("1", "true", "on", "yes")
        payload = request.data.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload) if payload.strip() else {}
            except json.JSONDecodeError as exc:
                raise ValidationAppError("payload must be JSON.") from exc
        if not isinstance(payload, dict):
            payload = {}
        runner = analyzers.RUNNERS[mode]
        if mode == "mobile":
            upload = request.FILES.get("package")
            raw = upload.read() if upload else None
            name = getattr(upload, "name", "") if upload else ""
            result = runner(payload, confirm, package_bytes=raw, filename=name)
        else:
            result = runner(payload, bool(confirm))
        result["mode"] = meta
        return ok(result)
