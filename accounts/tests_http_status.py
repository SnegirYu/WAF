from django.test import Client, TestCase, override_settings

from accounts.api.http_status import SUPPORTED_STATUS_CODES
from accounts.api.utils import PROBLEM_CATALOG, SUCCESS_CATALOG


class HttpStatusSupportTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_catalog_lists_all_required_codes(self):
        response = self.client.get("/api/v1/reference/http-status/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        listed = {
            item["code"]
            for group in data["supported"].values()
            for item in group
        }
        self.assertEqual(listed, set(SUPPORTED_STATUS_CODES))
        self.assertEqual(len(SUCCESS_CATALOG), 3)
        self.assertIn(418, PROBLEM_CATALOG)
        self.assertIn(504, PROBLEM_CATALOG)

    def test_demo_returns_problem_details_for_401(self):
        response = self.client.get("/api/v1/reference/http-status/401/")
        self.assertEqual(response.status_code, 401)
        body = response.json()
        self.assertEqual(body["title"], "Unauthorized")
        self.assertIn("requestId", body)
        self.assertIn("X-Request-Id", response.headers)

    def test_demo_returns_success_for_202(self):
        response = self.client.get("/api/v1/reference/http-status/202/")
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["status"], 202)

    def test_coffee_content_type_returns_418(self):
        response = self.client.post(
            "/api/v1/auth/register/",
            data="brew",
            content_type="application/coffee",
        )
        self.assertEqual(response.status_code, 418)
        self.assertEqual(response.json()["title"], "I'm a teapot")

    def test_demo_cannot_fake_418(self):
        response = self.client.get("/api/v1/reference/http-status/418/")
        self.assertEqual(response.status_code, 400)

    @override_settings(API_MAX_URI_LENGTH=50)
    def test_uri_too_long_returns_414(self):
        response = self.client.get("/api/v1/sites/" + "x" * 100)
        self.assertEqual(response.status_code, 414)
        self.assertEqual(response.json()["title"], "URI Too Long")

    def test_unsupported_method_returns_405(self):
        response = self.client.delete("/api/v1/auth/register/")
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json()["title"], "Method Not Allowed")

    def test_unsupported_media_type_returns_415(self):
        response = self.client.post(
            "/api/v1/auth/register/",
            data="not json",
            content_type="text/plain",
        )
        self.assertEqual(response.status_code, 415)
        self.assertEqual(response.json()["title"], "Unsupported Media Type")

    def test_unknown_demo_code_returns_400(self):
        response = self.client.get("/api/v1/reference/http-status/999/")
        self.assertEqual(response.status_code, 400)
