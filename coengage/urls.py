from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    ChangePasswordView,
    PasswordReset,
    RegisterView,
    RequestPasswordReset,
    ResendOTP,
    UserViewSet,
    VerifyEmail,
)

router = DefaultRouter()
router.register(r"users", UserViewSet)

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("register/verify_email/", VerifyEmail.as_view(), name="verify-email"),
    path("register/resend_otp/", ResendOTP.as_view(), name="resend-otp"),
    path(
        "users/password_reset/request/",
        RequestPasswordReset.as_view(),
        name="request-password-reset",
    ),
    path("users/password_reset/", PasswordReset.as_view(), name="password-reset"),
    path(
        "users/password_change/", ChangePasswordView.as_view(), name="change-password"
    ),
    path("", include(router.urls)),
]
