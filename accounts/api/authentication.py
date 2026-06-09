from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied

from accounts.api.permissions import extract_bearer_or_api_key, get_client_ip
from accounts.models import AccessToken


class AccessTokenAuthentication(BaseAuthentication):
    """
    Bearer или X-API-Key. Без credentials — anonymous (далее 401 через permission).
    authenticate_header нужен DRF, иначе NotAuthenticated превращается в 403.
    """

    keyword = "Bearer"

    def authenticate(self, request):
        token_value = extract_bearer_or_api_key(request)
        if not token_value:
            return None

        try:
            token = AccessToken.objects.get(token=str(token_value), is_active=True)
        except AccessToken.DoesNotExist:
            raise AuthenticationFailed("Недействительный или отсутствующий токен доступа.")

        client_ip = get_client_ip(request)
        if client_ip in token.get_blocked_ips_list():
            raise PermissionDenied("IP-адрес заблокирован для данного токена.")

        request.token = token
        return (token.user, token)

    def authenticate_header(self, request):
        return self.keyword
