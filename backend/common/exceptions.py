"""Centralized error handling.

Ensures the API never leaks Python tracebacks or internal details to
clients. All errors are logged server-side and returned using the
platform's standard error envelope:

    {"success": false, "error": {"code": ..., "message": ..., "details": {}}}
"""
import logging
import uuid

from django.http import Http404
from rest_framework import exceptions as drf_exceptions
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler

logger = logging.getLogger("django")


class ApplicationError(Exception):
    """Base class for expected, user-facing application errors."""

    code = "APPLICATION_ERROR"
    status_code = 400

    def __init__(self, message, details=None, code=None, status_code=None):
        self.message = message
        self.details = details or {}
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code
        super().__init__(message)


class ValidationAppError(ApplicationError):
    code = "VALIDATION_ERROR"
    status_code = 400


class PermissionDeniedAppError(ApplicationError):
    code = "PERMISSION_DENIED"
    status_code = 403


class NotFoundAppError(ApplicationError):
    code = "NOT_FOUND"
    status_code = 404


class ConflictAppError(ApplicationError):
    code = "CONFLICT"
    status_code = 409


class ServiceUnavailableAppError(ApplicationError):
    code = "SERVICE_UNAVAILABLE"
    status_code = 503


class UnsafeUploadError(ApplicationError):
    code = "UNSAFE_UPLOAD"
    status_code = 400


def _error_response(code, message, details, status_code):
    return Response(
        {"success": False, "error": {"code": code, "message": message, "details": details or {}}},
        status=status_code,
    )


def custom_exception_handler(exc, context):
    if isinstance(exc, ApplicationError):
        return _error_response(exc.code, exc.message, exc.details, exc.status_code)

    response = drf_exception_handler(exc, context)

    if response is not None:
        code = "ERROR"
        message = "Request failed."
        details = {}

        if isinstance(exc, drf_exceptions.ValidationError):
            code = "VALIDATION_ERROR"
            message = "Invalid request."
            details = response.data if isinstance(response.data, dict) else {"errors": response.data}
        elif isinstance(exc, drf_exceptions.AuthenticationFailed) or isinstance(exc, drf_exceptions.NotAuthenticated):
            code = "AUTHENTICATION_FAILED"
            message = "Authentication credentials were not provided or are invalid."
        elif isinstance(exc, drf_exceptions.PermissionDenied):
            code = "PERMISSION_DENIED"
            message = "You do not have permission to perform this action."
        elif isinstance(exc, (drf_exceptions.NotFound, Http404)):
            code = "NOT_FOUND"
            message = "The requested resource was not found."
        elif isinstance(exc, drf_exceptions.Throttled):
            code = "RATE_LIMITED"
            message = "Too many requests. Please slow down."
            details = {"retry_after_seconds": exc.wait}

        return _error_response(code, message, details, response.status_code)

    # Unhandled exception: log full detail server-side, return opaque error.
    error_id = uuid.uuid4().hex
    logger.exception("Unhandled exception [error_id=%s]", error_id)
    return _error_response(
        "INTERNAL_ERROR",
        "An unexpected error occurred. Please try again or contact support.",
        {"error_id": error_id} if error_id else {},
        500,
    )
