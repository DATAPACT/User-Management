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

"""
1. Define the route in urls.py
path("login/", views.login, name="login")
2. Use its name in the template
{% url 'login' %}
Examples from your project:
- name="login" -> {% url 'login' %} -> /login/
- name="register" -> {% url 'register' %} -> /register/
- name="manage_account" -> {% url 'manage_account' %} -> /manage-account/

Why this is better than hardcoding:
- if the path changes later, templates still work as long as the route name stays the same
Example:
path("sign-in/", views.login, name="login")
Then {% url 'login' %} automatically becomes /sign-in/ without changing the template.
"""

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", views.index_view, name="index"),

    path("login/", views.login, name="login"),
    path("register/", views.register, name="register"),
    path("manage-account/", views.manage_account, name="manage_account"),
    path("reset-password/", views.reset_password_view, name="reset_password"),
    path("logout/", views.logout_view, name="logout"),
    path("check-user-email/", views.check_user_email, name="check_user_email"),
    path("check-username/", views.check_username, name="check_username"),
    path("check-strong-password/", views.check_strong_password, name="check_strong_password"),
    path("check-phone-number/", views.check_phone_number, name="check_phone_number"),
]
