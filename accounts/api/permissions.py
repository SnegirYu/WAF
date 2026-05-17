from rest_framework.permissions import BasePermission

from accounts.models import AccessToken


def _header_value(value) -> str:
    if value is None or value == "":
        return ""
    return str(value).strip()


def get_client_ip(request) -> str:
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")


def extract_bearer_or_api_key(request) -> str | None:
    """
    Extract API token from Authorization: Bearer <token> or X-API-Key header.
    Returns None when no credentials are present.
    """
    auth_header = _header_value(request.headers.get("Authorization", ""))
    if auth_header.startswith("Bearer "):
        value = auth_header.split(" ", 1)[1].strip()
        return value or None

    api_key = _header_value(request.headers.get("X-API-Key", ""))
    if api_key:
        return api_key

    return None


def resolve_access_token(request) -> AccessToken | None:
    token_value = extract_bearer_or_api_key(request)
    if not token_value:
        return None
    try:
        return AccessToken.objects.get(token=str(token_value), is_active=True)
    except AccessToken.DoesNotExist:
        return None


class IsTokenAuthenticated(BasePermission):
    """
    Разрешение на основе токена доступа.
    Поддерживает: Authorization: Bearer <token> и заголовок X-API-Key.
    """
    message = "Недействительный или отсутствующий токен доступа."

    def has_permission(self, request, view):
        return bool(getattr(request, "token", None))


class IsAdminTokenAuthenticated(IsTokenAuthenticated):
    """
    Разрешение: токен + пользователь является суперпользователем.
    """
    message = "Требуются права администратора."

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        return request.token.user.is_superuser


class IsTokenOrSessionAuthenticated(IsTokenAuthenticated):
    """
    Разрешение: либо Bearer/API-Key, либо обычная Django-сессия.
    Удобно для серверных HTML-страниц, которые вызывают API через fetch.
    """

    def has_permission(self, request, view):
        if super().has_permission(request, view):
            return True
        return bool(getattr(request, "user", None) and request.user.is_authenticated)
