"""
URL configuration for user_management_frontend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", views.index_view, name="index"),
    path("login/", views.login, name="login"),
    # path("sign-up/", views.sign_up_view, name="sign_up"),
    path("register/", views.register, name="register"),
    path("manage-account/", views.manage_account_view, name="manage_account"),
    path("check-user-email/", views.check_user_email, name="check_user_email"),
    path("check-username/", views.check_username, name="check_username"),
    path("check-strong-password/", views.check_strong_password, name="check_strong_password"),
]
