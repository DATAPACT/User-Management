from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import clear_script_prefix, get_script_prefix

from .base_path import AppBasePathMiddleware


class AppBasePathMiddlewareTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def tearDown(self):
        clear_script_prefix()

    @override_settings(
        APP_BASE_PATH="/user-management",
        APP_REQUEST_PREFIXES=("/user-management",),
    )
    def test_default_path_is_stripped(self):
        request = self.factory.get("/user-management/login/")

        middleware = AppBasePathMiddleware(lambda req: HttpResponse("ok"))
        middleware(request)

        self.assertEqual(request.path_info, "/login/")
        self.assertEqual(request.path, "/user-management/login/")
        self.assertEqual(request.META["SCRIPT_NAME"], "/user-management")
        self.assertEqual(get_script_prefix(), "/user-management/")

    @override_settings(
        APP_BASE_PATH="/datapact/user-management",
        APP_REQUEST_PREFIXES=("/datapact/user-management", "/user-management"),
    )
    def test_project_prefixed_browser_path_is_stripped(self):
        request = self.factory.get("/datapact/user-management/login/")

        middleware = AppBasePathMiddleware(lambda req: HttpResponse("ok"))
        middleware(request)

        self.assertEqual(request.path_info, "/login/")
        self.assertEqual(request.path, "/datapact/user-management/login/")
        self.assertEqual(request.META["SCRIPT_NAME"], "/datapact/user-management")
        self.assertEqual(get_script_prefix(), "/datapact/user-management/")

    @override_settings(
        APP_BASE_PATH="/datapact/user-management",
        APP_REQUEST_PREFIXES=("/datapact/user-management", "/user-management"),
    )
    def test_root_upstream_path_keeps_external_script_prefix(self):
        request = self.factory.get("/login/")

        middleware = AppBasePathMiddleware(lambda req: HttpResponse("ok"))
        middleware(request)

        self.assertEqual(request.path_info, "/login/")
        self.assertEqual(request.META["SCRIPT_NAME"], "/datapact/user-management")
        self.assertEqual(get_script_prefix(), "/datapact/user-management/")

    @override_settings(
        APP_BASE_PATH="/upcast/user-management",
        APP_REQUEST_PREFIXES=("/upcast/user-management", "/user-management"),
    )
    def test_rewritten_default_prefix_is_accepted(self):
        request = self.factory.get("/user-management/reset-password/")

        middleware = AppBasePathMiddleware(lambda req: HttpResponse("ok"))
        middleware(request)

        self.assertEqual(request.path_info, "/reset-password/")
        self.assertEqual(request.path, "/upcast/user-management/reset-password/")
        self.assertEqual(request.META["SCRIPT_NAME"], "/upcast/user-management")
        self.assertEqual(get_script_prefix(), "/upcast/user-management/")
