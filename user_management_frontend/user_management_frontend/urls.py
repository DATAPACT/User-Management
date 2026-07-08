import re

from django.conf import settings
from django.contrib import admin
from django.contrib.staticfiles.views import serve as staticfiles_serve
from django.urls import path, re_path

from . import views


urlpatterns = [
    path("admin/", admin.site.urls),
    path("", views.index_view, name="index"),
    path("login/", views.login, name="login"),
    path("register/", views.register, name="register"),
    path("manage-account/", views.manage_account, name="manage_account"),
    path("search-user/", views.search_user, name="search_user"),
    path("admin-manage/", views.admin_manage, name="admin_manage"),
    path("admin-manage/search-users/", views.admin_search_user, name="admin_search_user"),
    path("admin-manage/delete/<str:user_id>/", views.admin_delete_user, name="admin_delete_user"),
    path("reset-password/", views.reset_password_view, name="reset_password"),
    path("logout/", views.logout_view, name="logout"),
    path("check-user-email/", views.check_user_email, name="check_user_email"),
    path("check-username/", views.check_username, name="check_username"),
    path("check-strong-password/", views.check_strong_password, name="check_strong_password"),
    path("check-phone-number/", views.check_phone_number, name="check_phone_number"),
]

if settings.DEBUG:
    app_base_path = re.escape(settings.APP_BASE_PATH.strip("/"))
    urlpatterns += [
        re_path(r"^static/(?P<path>.*)$", staticfiles_serve),
    ]
    if app_base_path:
        urlpatterns += [
            re_path(rf"^{app_base_path}/static/(?P<path>.*)$", staticfiles_serve),
        ]
