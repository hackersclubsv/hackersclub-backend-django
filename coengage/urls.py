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
router.register(r"users", UserViewSet, basename="users")
router.register(r"posts", PostViewSet, basename="posts")

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
        r"^posts/(?P<post_slug>[-\w]+)/comments/$",
        CommentViewSet.as_view({"get": "list", "post": "create"}),
        name="post-comments-list-create",
    ),
    re_path(
        r"^posts/(?P<post_slug>[-\w]+)/comments/(?P<slug>[-\w]+)/$",
        CommentViewSet.as_view(
            {
                "get": "retrieve",
                "put": "update",
                "patch": "partial_update",
                "delete": "destroy",
            }
        ),
        name="post-comments-detail",
    ),
    re_path(
        r"^posts/(?P<post_slug>[-\w]+)/vote/$",
        PostVoteViewSet.as_view({"post": "create"}),
        name="post-vote",
    ),
    re_path(
        r"^posts/(?P<post_slug>[-\w]+)/comments/(?P<comment_slug>[-\w]+)/vote/$",
        CommentVoteViewSet.as_view({"post": "create"}),
        name="comment-vote",
    ),
    path("", include(router.urls)),
]
