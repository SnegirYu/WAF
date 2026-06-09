"""
Глобальный обработчик исключений DRF.
Преобразует стандартные ошибки DRF в формат Problem Details (RFC 7807/9457).
"""
from rest_framework.views import exception_handler
from accounts.api.http_status import SUPPORTED_ERROR_CODES
from accounts.api.utils import problem_response


def custom_exception_handler(exc, context):
    """
    Вызывается DRF при необработанном исключении.
    Возвращает Problem Details вместо стандартного JSON.
    """
    response = exception_handler(exc, context)

    request = context.get("request")

    if response is not None:
        status_code = response.status_code
        if status_code not in SUPPORTED_ERROR_CODES:
            status_code = 500

        drf_detail = None
        if isinstance(response.data, dict):
            drf_detail = response.data.get("detail")
        elif isinstance(response.data, list) and response.data:
            drf_detail = str(response.data[0])

        detail_str = str(drf_detail) if drf_detail else None
        extra = None
        if status_code == 405 and isinstance(response.data, dict) and "allowed_methods" in response.data:
            extra = {"allowedMethods": response.data.get("allowed_methods")}

        return problem_response(status_code, detail=detail_str, request=request, extra=extra)

    # Необработанное исключение Python → 500
    return problem_response(500, request=request)
