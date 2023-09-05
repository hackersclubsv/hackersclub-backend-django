from django.urls import include, path, re_path
from rest_framework.routers import DefaultRouter

from .views import (
    ChangePasswordView,
    CommentViewSet,
    CommentVoteViewSet,
    PasswordReset,
    PostViewSet,
    PostVoteViewSet,
    RegisterView,
    RequestPasswordReset,
    ResendOTP,
    UserViewSet,
    VerifyEmail,
)

router = DefaultRouter()
router.register(r"users", UserViewSet)
router.register(r"posts", PostViewSet)
router.register(r"comments", CommentViewSet)

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
    re_path(
        r"^posts/(?P<post_id>\d+)/vote/$",
        PostVoteViewSet.as_view({"post": "create"}),
        name="post-vote",
    ),
    re_path(
        r"^comments/(?P<comment_id>\d+)/vote/$",
        CommentVoteViewSet.as_view({"post": "create"}),
        name="comment-vote",
    ),
    re_path(
        r"^comments/getCommentsByPostID/$",
        CommentViewSet.as_view({"get": "getCommentsByPostID"}),
        name="get-comments-by-post-id",
    ),
    re_path(
        r"^comments/getCommentsByPostSlug/$",
        CommentViewSet.as_view({"get": "getCommentsByPostSlug"}),
        name="get-comments-by-post-id",
    ),
    path("", include(router.urls)),
]
