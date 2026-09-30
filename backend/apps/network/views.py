from rest_framework import status
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from common.exceptions import ValidationAppError

from . import services


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"success": True, "data": data if data is not None else {}}, status=status_code)


class NetworkSelfView(APIView):
    def get(self, request):
        return ok(services.client_identity(request))


class NetworkDnsView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "network"

    def post(self, request):
        return ok(services.dns_lookup(request.data.get("host", "")))


class NetworkIpView(APIView):
    def post(self, request):
        return ok(services.classify_ip(request.data.get("ip", "")))


class NetworkLocalPortsView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "network"

    def post(self, request):
        return ok(services.localhost_ports())


class NetworkHeadersView(APIView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "network"

    def post(self, request):
        if not request.data.get("confirm_owned"):
            raise ValidationAppError("Confirm you operate this URL before checking it.")
        return ok(services.http_security_headers(request.data.get("url", "")))
