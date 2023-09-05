import os
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.files.storage import default_storage
from django.db import transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import permissions, status, viewsets
from rest_framework.exceptions import NotFound
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import Category, Comment, CommentVote, Image, Post, PostVote, Tag
from .serializers import (
    CategorySerializer,
    ChangePasswordSerializer,
    CommentSerializer,
    CommentVoteSerializer,
    PasswordResetSerializer,
    PostSerializer,
    PostVoteSerializer,
    RegisterSerializer,
    RequestPasswordResetSerializer,
    ResendOTPSerializer,
    TagSerializer,
    UserSerializer,
    VerifyEmailSerializer,
)
from .utilities import (
    generate_otp,
    handle_and_save_images,
    handle_user_profile_picture_upload,
    send_email_ses,
)

User = get_user_model()


class IsUserOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj == request.user


class IsUserOwnerOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj == request.user or request.user.role == User.ADMIN


class IsPostOrCommentOwnerOrAdmin(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.user == request.user or request.user.role == User.ADMIN


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    # lookup_field = 'email'
    permission_classes = [IsUserOwnerOrReadOnly]
    authentication_classes = [JWTAuthentication]
    http_method_names = ["get", "put", "patch", "head", "options", "delete"]

    def get_permissions(self):
        if getattr(self, "swagger_fake_view", False):
            # VIEW USED FOR SCHEMA GENERATION PURPOSES
            return []
        if self.action == "destroy":
            self.permission_classes = [IsUserOwnerOrAdmin]
        return super(UserViewSet, self).get_permissions()

    def create(self, request, *args, **kwargs):
        raise NotFound("This method is not available.")

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if "profile_picture" in request.FILES:
            instance.profile_picture = handle_user_profile_picture_upload(
                instance, request.FILES["profile_picture"]
            )
            instance.save()
        return Response(serializer.data)

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(
            {"status": "User successfully deleted."}, status=status.HTTP_204_NO_CONTENT
        )


class RegisterView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        try:
            user = User.objects.get(email=request.data["email"])
        except User.DoesNotExist:
            return Response(
                {"error": "User could not be created."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        email_response = send_email_ses(user.username, user.otp, user.email)

        if not email_response["success"]:
            return Response(
                {"email_error": "OTP not sent", "message": email_response["message"]},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {"status": "Registration successful. Please verify your email."},
            status=status.HTTP_201_CREATED,
        )


class VerifyEmail(APIView):
    serializer_class = VerifyEmailSerializer

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        otp = serializer.validated_data["otp"]

        user = get_object_or_404(User, email=email)

        # Check if OTP has expired
        if timezone.now() > user.otp_expiration:
            return Response(
                {"status": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Check if OTP verification is blocked due to too many attempts
        if (
            user.otp_attempts >= 3
            and (timezone.now() - user.otp_attempts_timestamp).total_seconds() < 600
        ):
            return Response(
                {"status": "Too many failed attempts. Please try again later."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user.is_verified:
            return Response(
                {"status": "Email already verified, please Login"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        elif otp == user.otp:
            user.is_verified = True
            user.otp = None
            user.otp_attempts = 0
            user.otp_attempts_timestamp = None
            user.save()

            return Response(
                {"status": "Email verified, please proceed to Login page"},
                status=status.HTTP_200_OK,
            )
        else:
            user.otp_attempts += 1
            if user.otp_attempts == 1:
                user.otp_attempts_timestamp = timezone.now()
            user.save()
            return Response(
                {"status": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST
            )


class ResendOTP(APIView):
    serializer_class = ResendOTPSerializer

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        user = get_object_or_404(User, email=email)

        if user.is_verified:
            return Response(
                {"status": "Email already verified, please Login"},
                status=status.HTTP_200_OK,
            )
        user.otp = generate_otp()
        user.otp_created_at = timezone.now()
        user.otp_expiration = timezone.now() + timedelta(minutes=10)
        user.save()

        email_response = send_email_ses(user.username, user.otp, user.email)
        if not email_response["success"]:
            return Response(
                {"email_error": "OTP not sent", "message": email_response["message"]},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {"status": "New OTP sent, please check your email."},
            status=status.HTTP_200_OK,
        )


class RequestPasswordReset(APIView):
    serializer_class = RequestPasswordResetSerializer
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        user = get_object_or_404(User, email=email)

        user.otp = generate_otp()
        user.otp_created_at = timezone.now()
        user.otp_expiration = timezone.now() + timedelta(minutes=10)
        user.save()

        email_response = send_email_ses(user.username, user.otp, user.email)
        if not email_response["success"]:
            return Response(
                {"email_error": "OTP not sent", "message": email_response["message"]},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response(
            {"status": "OTP sent, please check your email."},
            status=status.HTTP_200_OK,
        )


class PasswordReset(APIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp = serializer.validated_data["otp"]
        email = serializer.validated_data["email"]
        new_password = serializer.validated_data["password"]
        user = get_object_or_404(User, email=email)

        # Check if OTP has expired
        if (
            otp is not None
            and user.otp is not None
            and timezone.now() > user.otp_expiration
        ):
            return Response(
                {"status": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST
            )

        if otp == int(user.otp):
            user.set_password(new_password)
            user.otp = None
            user.otp_expiration = None
            user.save()

            return Response(
                {"status": "Password successfully reset."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"status": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST
            )


class ChangePasswordView(APIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @transaction.atomic
    def patch(self, request, *args, **kwargs):
        user = request.user
        print(user.email)
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        # Check old password
        if not user.check_password(serializer.validated_data.get("old_password")):
            return Response(
                {"status": "Wrong old password."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.set_password(serializer.validated_data.get("new_password"))
        user.save()

        return Response(
            {"status": "Password updated successfully"}, status=status.HTTP_200_OK
        )


class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsPostOrCommentOwnerOrAdmin]

    def get_permissions(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return [IsPostOrCommentOwnerOrAdmin()]
        return [AllowAny()]

    def get_queryset(self):
        queryset = (
            Post.objects.filter(is_deleted=False)
            .select_related("user")
            .annotate(total_comments=Count("comments"))
        )
        # Get category id from query params
        category_id = self.request.query_params.get("category_id", None)
        if category_id is not None:
            queryset = queryset.filter(category_id=category_id)
        return queryset

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)

        post_instance = serializer.instance
        handle_and_save_images(request, post_instance, "images")

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)

        handle_and_save_images(request, instance, "images")

        return Response(serializer.data)

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        post = self.get_object()
        post.is_deleted = True
        post.save()
        return Response(
            {"status": "Post deleted successfully"}, status=status.HTTP_204_NO_CONTENT
        )

    @action(
        detail=False, methods=["get"], url_path="(?P<slug>.+)", url_name="by_slug"
    )  # not by id (pk), so set detail=False
    def get_by_slug(self, request, slug=None):
        post = Post.objects.filter(slug=slug).first()
        if post is None:
            return Response(
                {"error": "Post not found."}, status=status.HTTP_404_NOT_FOUND
            )

        serializer = self.get_serializer(post)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PostVoteViewSet(viewsets.ModelViewSet):
    queryset = PostVote.objects.all()
    serializer_class = PostVoteSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        print("called voteviewset")

        user = request.user
        post_id = self.kwargs["post_id"]
        vote_value = request.data.get("vote")

        vote, created = PostVote.objects.get_or_create(
            user=user, post_id=post_id, defaults={"vote": vote_value}
        )

        if not created:
            if vote.vote == vote_value:
                vote.delete()
                return Response({"status": "Vote removed"}, status=status.HTTP_200_OK)
            else:
                vote.vote = vote_value
                vote.save()

        serializer = self.get_serializer(vote)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer


class TagViewSet(viewsets.ModelViewSet):
    queryset = Tag.objects.all()
    serializer_class = TagSerializer


class CommentVoteViewSet(viewsets.ModelViewSet):
    queryset = CommentVote.objects.all()
    serializer_class = CommentVoteSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        user = request.user
        comment_id = self.kwargs["comment_id"]
        vote_value = request.data.get("vote")

        vote, created = CommentVote.objects.get_or_create(
            user=user, comment_id=comment_id, defaults={"vote": vote_value}
        )

        if not created:
            if vote.vote == vote_value:
                vote.delete()
                return Response({"status": "Vote removed"}, status=status.HTTP_200_OK)
            else:
                vote.vote = vote_value
                vote.save()

        serializer = self.get_serializer(vote)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    authentication_classes = [JWTAuthentication]

    def get_permissions(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return [IsPostOrCommentOwnerOrAdmin()]
        return [AllowAny()]

    def get_queryset(self):
        return Comment.objects.filter(is_deleted=False)  # Fixed the queryset

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)

        comment_instance = serializer.instance
        handle_and_save_images(request, comment_instance, "images")

        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)

        handle_and_save_images(request, instance, "images")

        return Response(serializer.data)

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        comment = self.get_object()
        comment.is_deleted = True
        comment.save()
        return Response(
            {"status": "Comment deleted successfully"},
            status=status.HTTP_204_NO_CONTENT,
        )

    @action(detail=False, methods=["GET"])
    def getCommentsByPostID(self, request):
        post_id = request.query_params.get("id", None)
        if post_id is None:
            return Response(
                {"error": "No post id was provided."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        comments = Comment.objects.filter(post_id=post_id, is_deleted=False)
        # From the docs: https://www.django-rest-framework.org/api-guide/serializers/ 
        # There are some cases where you need to provide extra context to the serializer in addition to the object being serialized. One common case is if you're using a serializer that includes hyperlinked relations, which requires the serializer to have access to the current request so that it can properly generate fully qualified URLs.
        serializer = CommentSerializer(
            comments, many=True, context={"request": request}
        )
        return Response(serializer.data)

    @action(detail=False, methods=["GET"])
    def getCommentsByPostSlug(self, request):
        slug = request.query_params.get("slug", None)
        if slug is None:
            return Response(
                {"error": "No slug was provided."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            post = Post.objects.get(slug=slug)
        except Post.DoesNotExist:
            raise Http404("Post with given slug does not exist.")
            
        comments = Comment.objects.filter(post=post, is_deleted=False)
        serializer = CommentSerializer(comments, many=True, context={"request": request})
        return Response(serializer.data)
