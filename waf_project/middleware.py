"""
Security middleware:
  - RequestContextMiddleware   — UUIDv7 request ID, HTTP logging, X-Request-Id
  - RejectCsrfTokenInQueryMiddleware — CSRF token must not appear in GET params
  - ApiRateLimitMiddleware     — 10 req/min per IP and per API token on /api/
"""
from __future__ import annotations

import logging
import re
import time

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse

from accounts.api.permissions import extract_bearer_or_api_key, get_client_ip
from accounts.api.request_semantics import teapot_detail_for_request
from accounts.api.utils import problem_json_response
from waf_project.rate_limit import is_rate_limited
from waf_project.request_context import reset_request_id, set_request_id

logger = logging.getLogger("waf.http")

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[7][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_API_PREFIX = "/api/"
_PUBLIC_API_PATHS = frozenset(
    p.rstrip("/") + "/"
    for p in (
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/token",
        "/api/v1/waf-status",
        "/api/v1/reference/http-status",
        "/api/schema",
        "/api/docs",
        "/api/redoc",
    )
)


def _is_public_api_path(path: str) -> bool:
    normalized = path if path.endswith("/") else path + "/"
    if normalized in _PUBLIC_API_PATHS:
        return True
    if normalized.startswith("/api/v1/auth/verify-email/"):
        return True
    if normalized.startswith("/api/v1/reference/http-status/"):
        return True
    return False


class RequestContextMiddleware:
    """Assign UUIDv7 request ID, log every HTTP request, echo X-Request-Id."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        from accounts.api.utils import generate_uuid7

        incoming = (request.headers.get("X-Request-Id") or "").strip()
        if incoming and _UUID_RE.match(incoming):
            request_id = incoming.lower()
        else:
            request_id = generate_uuid7()

        request.request_id = request_id
        ctx_token = set_request_id(request_id)
        started = time.perf_counter()

        logger.info(
            "request_started method=%s path=%s ip=%s",
            request.method,
            request.get_full_path(),
            get_client_ip(request),
            extra={"request_id": request_id},
        )

        try:
            response = self.get_response(request)
        except Exception:
            duration_ms = int((time.perf_counter() - started) * 1000)
            logger.exception(
                "request_failed method=%s path=%s duration_ms=%s",
                request.method,
                request.get_full_path(),
                duration_ms,
                extra={"request_id": request_id},
            )
            raise
        finally:
            reset_request_id(ctx_token)

        duration_ms = int((time.perf_counter() - started) * 1000)
        response["X-Request-Id"] = request_id

        logger.info(
            "request_finished method=%s path=%s status=%s duration_ms=%s ip=%s",
            request.method,
            request.get_full_path(),
            response.status_code,
            duration_ms,
            get_client_ip(request),
            extra={"request_id": request_id},
        )
        return response


class ApiSemantic418Middleware:
    """418 — запрос семантически неприменим к API (HTCPCP, coffee, и т.п.)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.path.startswith(_API_PREFIX):
            detail = teapot_detail_for_request(request)
            if detail:
                return problem_json_response(
                    418,
                    detail=detail,
                    request_id=getattr(request, "request_id", None),
                )
        return self.get_response(request)


class ApiUriTooLongMiddleware:
    """414 URI Too Long для запросов к API."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.path.startswith(_API_PREFIX):
            max_len = int(getattr(settings, "API_MAX_URI_LENGTH", 2048))
            if len(request.get_full_path()) > max_len:
                return problem_json_response(
                    414,
                    request_id=getattr(request, "request_id", None),
                )
        return self.get_response(request)


class RejectCsrfTokenInQueryMiddleware:
    """Reject CSRF tokens passed via GET query parameters."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.method == "GET" and "csrfmiddlewaretoken" in request.GET:
            request_id = getattr(request, "request_id", None)
            if request.path.startswith(_API_PREFIX):
                return problem_json_response(
                    400,
                    detail="CSRF-токен не должен передаваться через GET-параметры.",
                    request_id=request_id,
                )
            return JsonResponse(
                {"detail": "CSRF-токен не должен передаваться через GET-параметры."},
                status=400,
            )
        return self.get_response(request)


class ApiRateLimitMiddleware:
    """Rate limit API traffic: 10 requests/minute per IP and per Bearer/API-Key."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        path = request.path
        if not path.startswith(_API_PREFIX) or _is_public_api_path(path):
            return self.get_response(request)

        client_ip = get_client_ip(request) or "unknown"
        keys = [f"ip:{client_ip}"]

        token_value = extract_bearer_or_api_key(request)
        if token_value:
            keys.append(f"token:{token_value!s}")

        for key in keys:
            if is_rate_limited(key):
                retry_after = str(getattr(settings, "API_RATE_LIMIT_WINDOW", 60))
                response = problem_json_response(
                    429,
                    detail="Превышен лимит запросов (10 в минуту). Повторите позже.",
                    request_id=getattr(request, "request_id", None),
                )
                response["Retry-After"] = retry_after
                return response

        return self.get_response(request)
