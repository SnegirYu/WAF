import re
import uuid

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from rest_framework.test import APIClient

from accounts.models import AccessToken

User = get_user_model()
_UUID7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


@override_settings(
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "security-tests",
        }
    },
    API_RATE_LIMIT=10,
    API_RATE_LIMIT_WINDOW=60,
)
class SecurityMiddlewareTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.api = APIClient()
        self.user = User.objects.create_user(
            username="secuser",
            email="sec@example.com",
            password="pass12345!",
            is_active=True,
        )
        self.token = AccessToken.objects.create(user=self.user, name="test-token")

    def test_request_id_header_on_html(self):
        response = self.client.get("/register/")
        self.assertEqual(response.status_code, 200)
        rid = response.headers.get("X-Request-Id", "")
        self.assertTrue(_UUID7_RE.match(rid), rid)

    def test_csrf_token_rejected_in_get_query(self):
        response = self.client.get("/register/?csrfmiddlewaretoken=fake")
        self.assertEqual(response.status_code, 400)

    def test_api_without_token_returns_401(self):
        response = self.api.get("/api/v1/sites/")
        self.assertEqual(response.status_code, 401)
        self.assertIn("requestId", response.json())
        self.assertTrue(_UUID7_RE.match(response.json()["requestId"]))
        self.assertEqual(
            response.headers.get("X-Request-Id"),
            response.json()["requestId"],
        )

    def test_api_with_bearer_token(self):
        self.api.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token.token!s}")
        response = self.api.get("/api/v1/sites/")
        self.assertIn(response.status_code, (200, 403))

    def test_api_with_x_api_key(self):
        self.api.credentials(HTTP_AUTHORIZATION="")
        response = self.api.get(
            "/api/v1/sites/",
            HTTP_X_API_KEY=str(self.token.token),
        )
        self.assertIn(response.status_code, (200, 403))

    def test_rate_limit_returns_429(self):
        for _ in range(11):
            response = self.api.get("/api/v1/sites/")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json()["title"], "Too Many Requests")
        self.assertIn("Retry-After", response.headers)

    def test_public_waf_status_not_rate_limited_heavily(self):
        for _ in range(15):
            response = self.client.get("/api/v1/waf-status/?domain=example.com")
        self.assertNotEqual(response.status_code, 429)
