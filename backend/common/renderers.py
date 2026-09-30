"""Ensures every successful API response uses the platform's standard
{"success": true, "data": ...} envelope - including responses produced by
DRF's built-in ModelViewSet actions (retrieve/create/update), which
return raw serializer data by default and would otherwise bypass the
envelope that custom APIViews (via the `ok()` helper) and the paginator
already apply by hand.
"""
from rest_framework.renderers import JSONRenderer


class EnvelopeJSONRenderer(JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        # 204 No Content and similar: preserve the default empty-body
        # behavior rather than rendering a JSON body onto a no-content response.
        if data is None:
            return super().render(None, accepted_media_type, renderer_context)

        # Already enveloped - paginated list responses (StandardResultsSetPagination),
        # custom APIView success responses (the `ok()` helper), and the
        # custom exception handler's error responses all set "success"
        # explicitly already. Don't double-wrap those.
        if isinstance(data, dict) and "success" in data:
            return super().render(data, accepted_media_type, renderer_context)

        wrapped = {"success": True, "data": data}
        return super().render(wrapped, accepted_media_type, renderer_context)
