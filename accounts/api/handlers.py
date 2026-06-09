"""Django HTTP error handlers для API (формат Problem Details)."""
from django.http import HttpRequest

from accounts.api.utils import problem_json_response


def error_413(request: HttpRequest, exception=None):
    return problem_json_response(413, request=request)


def error_414(request: HttpRequest, exception=None):
    return problem_json_response(414, request=request)
