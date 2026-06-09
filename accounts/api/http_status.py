"""
Обязательные поддерживаемые HTTP-коды API (2xx, 4xx, 5xx).
"""
from __future__ import annotations

from accounts.api.utils import PROBLEM_CATALOG, problem_response
from rest_framework.response import Response

# 2xx — успешные ответы (тело — JSON, не Problem Details)
SUCCESS_CATALOG: dict[int, tuple[str, str]] = {
    200: ("OK", "Запрос выполнен успешно."),
    201: ("Created", "Ресурс успешно создан."),
    202: ("Accepted", "Запрос принят к обработке."),
}

SUPPORTED_SUCCESS_CODES = frozenset(SUCCESS_CATALOG)
SUPPORTED_ERROR_CODES = frozenset(PROBLEM_CATALOG)
SUPPORTED_STATUS_CODES = SUPPORTED_SUCCESS_CODES | SUPPORTED_ERROR_CODES

# Не выдаётся через демо-эндпоинт — только при реальном некорректном запросе
DEMO_EXCLUDED_STATUS_CODES = frozenset({418})


def is_supported_status(code: int) -> bool:
    return code in SUPPORTED_STATUS_CODES


def is_demo_status(code: int) -> bool:
    return code in SUPPORTED_STATUS_CODES and code not in DEMO_EXCLUDED_STATUS_CODES


def success_response(
    data: dict | list | None = None,
    *,
    status: int = 200,
    request=None,
    detail: str | None = None,
) -> Response:
    if status not in SUCCESS_CATALOG:
        raise ValueError(f"Unsupported success status: {status}")
    title, default_detail = SUCCESS_CATALOG[status]
    body = data if data is not None else {
        "status": status,
        "title": title,
        "detail": detail or default_detail,
    }
    from accounts.api.utils import resolve_request_id

    response = Response(body, status=status)
    response["X-Request-Id"] = resolve_request_id(request=request)
    return response


def response_for_status(code: int, *, request=None, detail: str | None = None) -> Response:
    """Возвращает пример ответа для любого поддерживаемого кода."""
    if code in SUCCESS_CATALOG:
        return success_response(status=code, request=request, detail=detail)
    if code in PROBLEM_CATALOG:
        return problem_response(code, detail=detail, request=request)
    raise ValueError(f"Unsupported HTTP status: {code}")
