"""
Справочные эндпоинты поддерживаемых HTTP-кодов и демонстрация ответов.
"""
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.api.http_status import (
    DEMO_EXCLUDED_STATUS_CODES,
    SUCCESS_CATALOG,
    SUPPORTED_STATUS_CODES,
    is_demo_status,
    is_supported_status,
    response_for_status,
    success_response,
)
from accounts.api.serializers import ProblemDetailSerializer
from accounts.api.utils import PROBLEM_CATALOG, problem_response


def _catalog_payload() -> dict:
    return {
        "2xx": [
            {"code": code, "title": SUCCESS_CATALOG[code][0], "description": SUCCESS_CATALOG[code][1]}
            for code in sorted(SUCCESS_CATALOG)
        ],
        "4xx": [
            {
                "code": code,
                "title": PROBLEM_CATALOG[code][0],
                "description": PROBLEM_CATALOG[code][1],
                **(
                    {
                        "trigger": (
                            "Автоматически при семантически неприменимом запросе "
                            "(например, Content-Type: application/coffee, метод BREW, Accept: application/coffee)."
                        )
                    }
                    if code == 418
                    else {}
                ),
            }
            for code in sorted(c for c in PROBLEM_CATALOG if 400 <= c < 500)
        ],
        "5xx": [
            {"code": code, "title": PROBLEM_CATALOG[code][0], "description": PROBLEM_CATALOG[code][1]}
            for code in sorted(c for c in PROBLEM_CATALOG if 500 <= c < 600)
        ],
    }


@extend_schema(
    tags=["HTTP Status"],
    summary="Каталог поддерживаемых HTTP-кодов",
    description="Список всех обязательных кодов 2xx, 4xx и 5xx, которые поддерживает API.",
    responses={200: None},
    auth=[],
)
class HttpStatusCatalogView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request: Request) -> Response:
        return success_response(
            {"supported": _catalog_payload(), "total": len(SUPPORTED_STATUS_CODES)},
            request=request,
        )


@extend_schema(
    tags=["HTTP Status"],
    summary="Пример ответа для HTTP-кода",
    description=(
        "Возвращает образец успешного (2xx) или Problem Details (4xx/5xx) ответа "
        "для указанного поддерживаемого кода."
    ),
    parameters=[
        OpenApiParameter(
            "code",
            int,
            OpenApiParameter.PATH,
            required=True,
            description="HTTP-код (200, 201, 202, 400, …, 504)",
        ),
    ],
    responses={
        200: OpenApiResponse(description="2xx — успех"),
        201: OpenApiResponse(description="2xx — создано"),
        202: OpenApiResponse(description="2xx — принято"),
        400: OpenApiResponse(response=ProblemDetailSerializer),
        401: OpenApiResponse(response=ProblemDetailSerializer),
        403: OpenApiResponse(response=ProblemDetailSerializer),
        404: OpenApiResponse(response=ProblemDetailSerializer),
        405: OpenApiResponse(response=ProblemDetailSerializer),
        413: OpenApiResponse(response=ProblemDetailSerializer),
        414: OpenApiResponse(response=ProblemDetailSerializer),
        415: OpenApiResponse(response=ProblemDetailSerializer),
        429: OpenApiResponse(response=ProblemDetailSerializer),
        500: OpenApiResponse(response=ProblemDetailSerializer),
        501: OpenApiResponse(response=ProblemDetailSerializer),
        502: OpenApiResponse(response=ProblemDetailSerializer),
        503: OpenApiResponse(response=ProblemDetailSerializer),
        504: OpenApiResponse(response=ProblemDetailSerializer),
    },
    auth=[],
)
class HttpStatusDemoView(APIView):
    authentication_classes = []
    permission_classes = []

    def get(self, request: Request, code: int) -> Response:
        if not is_supported_status(code):
            return problem_response(
                400,
                detail=f"Код {code} не входит в список поддерживаемых. "
                f"Допустимые: {sorted(SUPPORTED_STATUS_CODES)}",
                request=request,
            )
        if code in DEMO_EXCLUDED_STATUS_CODES:
            return problem_response(
                400,
                detail=(
                    "418 I'm a teapot не вызывается через демо. "
                    "Отправьте семантически неприменимый запрос, например: "
                    "POST с Content-Type: application/coffee или метод BREW."
                ),
                request=request,
            )
        if not is_demo_status(code):
            return problem_response(400, request=request)
        return response_for_status(code, request=request)
