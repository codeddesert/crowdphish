from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from phishing import views

admin.site.site_header = "Crowdphish"
admin.site.site_title = "Crowdphish"
admin.site.index_title = "Reports and intel"

urlpatterns = [
    path("health/", views.health, name="health"),
    path("", views.lobby, name="lobby"),
    path("learn/", views.learn, name="learn"),
    path("accounts/login/", auth_views.LoginView.as_view(template_name="registration/login.html"), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("phishing/", include("phishing.urls")),
    path("api/phishing/", include("phishing.api_urls")),
    path("admin/", admin.site.urls),
]
