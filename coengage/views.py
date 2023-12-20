from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import DatabaseError, transaction
from django.db.models import Count
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import permissions, status, viewsets
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.generics import CreateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import Category, Comment, CommentVote, Post, PostVote, Tag
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
    send_email_sendgrid,
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
    lookup_field = "username"
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
        try:
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
        except DatabaseError:
            return Response({"error": "Database error occurred"}, status=500)
        except ValidationError as e:
            return Response({"error": str(e)}, status=400)
        except Exception as e:
            return Response({"error": str(e)}, status=500)

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(
                {"message": "User successfully deleted."},
                status=status.HTTP_204_NO_CONTENT,
            )
        except DatabaseError:
            return Response({"error": "Database error occurred"}, status=500)
        except Exception as e:
            return Response({"error": str(e)}, status=500)


class RegisterView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        try:
            # Check for existing users
            if User.objects.filter(email=request.data["email"]).exists():
                raise ValidationError("User with this email already exists.")

            # Create new user
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)

            # Send email
            user = User.objects.get(email=request.data["email"])
            email_response = send_email_sendgrid(user.username, user.otp, user.email)
            if not email_response["success"]:
                return Response(
                    {
                        "error": "OTP not sent",
                        "message": email_response["message"],
                    },
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )

            return Response(
                {"message": "Registration successful. Please verify your email."},
                status=status.HTTP_201_CREATED,
            )

        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError as de:
            return Response(
                {"error": "Database error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Error during registration: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred during registration."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class VerifyEmail(APIView):
    serializer_class = VerifyEmailSerializer
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data["email"]
            otp = serializer.validated_data["otp"]

            user = get_object_or_404(User, email=email)

            # Check if OTP has expired
            if timezone.now() > user.otp_expiration:
                return Response(
                    {"message": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST
                )

            # Check if OTP verification is blocked due to too many attempts
            if (
                user.otp_attempts >= 3
                and (timezone.now() - user.otp_attempts_timestamp).total_seconds() < 600
            ):
                return Response(
                    {"message": "Too many failed attempts. Please try again later."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if user.is_verified:
                return Response(
                    {"message": "Email already verified, please Login"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            elif otp == int(user.otp):
                user.is_verified = True
                user.otp = None
                user.otp_attempts = 0
                user.otp_attempts_timestamp = None
                user.save()

                return Response(
                    {"message": "Email verified, please proceed to Login page"},
                    status=status.HTTP_200_OK,
                )
            else:
                user.otp_attempts += 1
                if user.otp_attempts == 1:
                    user.otp_attempts_timestamp = timezone.now()
                user.save()
                return Response(
                    {"message": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST
                )
        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError:
            return Response(
                {"error": "Database error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Error during email verification: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred during email verification."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class ResendOTP(APIView):
    serializer_class = ResendOTPSerializer
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data["email"]
            user = get_object_or_404(User, email=email)

            if user.is_verified:
                return Response(
                    {"message": "Email already verified, please Login"},
                    status=status.HTTP_200_OK,
                )
            user.otp = generate_otp()
            user.otp_created_at = timezone.now()
            user.otp_expiration = timezone.now() + timedelta(minutes=10)
            user.save()

            email_response = send_email_sendgrid(user.username, user.otp, user.email)
            if not email_response["success"]:
                return Response(
                    {
                        "error": "OTP not sent",
                        "message": email_response["message"],
                    },
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )

            return Response(
                {"message": "New OTP sent, please check your email."},
                status=status.HTTP_200_OK,
            )

        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError:
            return Response(
                {"error": "Database error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Error during OTP resend: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred during OTP resend."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class RequestPasswordReset(APIView):
    serializer_class = RequestPasswordResetSerializer
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data["email"]
            user = get_object_or_404(User, email=email)

            user.otp = generate_otp()
            user.otp_created_at = timezone.now()
            user.otp_expiration = timezone.now() + timedelta(minutes=10)
            user.save()

            email_response = send_email_sendgrid(user.username, user.otp, user.email)
            if not email_response["success"]:
                return Response(
                    {
                        "error": "OTP not sent",
                        "message": email_response["message"],
                    },
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )

            return Response(
                {"message": "OTP sent, please check your email."},
                status=status.HTTP_200_OK,
            )

        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError:
            return Response(
                {"error": "Database error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Error during password reset request: {str(e)}")
            return Response(
                {
                    "error": "An unexpected error occurred during password reset request."
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class PasswordReset(APIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [AllowAny]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        try:
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
                    {"error": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST
                )

            if otp == int(user.otp):
                user.set_password(new_password)
                user.otp = None
                user.otp_expiration = None
                user.save()

                return Response(
                    {"message": "Password successfully reset."},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST
                )

        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError:
            return Response(
                {"error": "Database error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Error during password reset: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred during password reset."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class ChangePasswordView(APIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    @transaction.atomic
    def patch(self, request, *args, **kwargs):
        try:
            user = request.user
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)

            # Check old password
            if not user.check_password(serializer.validated_data.get("old_password")):
                return Response(
                    {"error": "Wrong old password."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user.set_password(serializer.validated_data.get("new_password"))
            user.save()

            return Response(
                {"message": "Password updated successfully"}, status=status.HTTP_200_OK
            )

        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError:
            return Response(
                {"error": "Database error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Error during password change: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred during password change."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class PostViewSet(viewsets.ModelViewSet):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    authentication_classes = [JWTAuthentication]
    lookup_field = "slug"

    def get_permissions(self):
        # SAFE_METHODS = GET, OPTIONS, HEAD
        if self.request.method not in permissions.SAFE_METHODS:
            return [IsPostOrCommentOwnerOrAdmin()]
        return [AllowAny()]

    def get_queryset(self):
        try:
            queryset = (
                Post.objects.filter(is_deleted=False)
                .select_related("user")
                .annotate(total_comments=Count("comments"))
            )
            category_id = self.request.query_params.get("category_id", None)
            if category_id is not None:
                queryset = queryset.filter(category_id=category_id)
            return queryset
        except DatabaseError:
            raise Exception("Database error while fetching posts.")

    def get_object(self):
        try:
            queryset = self.get_queryset()
            filter_kwargs = {self.lookup_field: self.kwargs["slug"]}
            obj = get_object_or_404(queryset, **filter_kwargs)
            self.check_object_permissions(self.request, obj)
            return obj
        except Http404:
            raise NotFound("The post with this slug does not exist.")
        except DatabaseError:
            return Response(
                {"error": "Database error occurred while fetching post."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Unexpected error: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(user=request.user)

            post_instance = serializer.instance
            handle_and_save_images(request, post_instance, "images")

            headers = self.get_success_headers(serializer.data)
            return Response(
                serializer.data, status=status.HTTP_201_CREATED, headers=headers
            )
        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError:
            return Response(
                {"error": "Database error occurred while creating post."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Unexpected error: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save(user=request.user)

            handle_and_save_images(request, instance, "images")

            return Response(serializer.data)
        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError:
            return Response(
                {"error": "Database error occurred while updating post."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Unexpected error: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        try:
            post = self.get_object()
            post.is_deleted = True
            post.save()
            return Response(
                {"message": "Post deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except DatabaseError:
            return Response(
                {"error": "Database error occurred while deleting post."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Unexpected error: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class PostVoteViewSet(viewsets.ModelViewSet):
    queryset = PostVote.objects.all()
    serializer_class = PostVoteSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        try:
            user = request.user
            post_slug = self.kwargs["post_slug"]
            vote_value = request.data.get("vote")

            post = get_object_or_404(Post, slug=post_slug)

            vote, created = PostVote.objects.get_or_create(
                user=user, post=post, defaults={"vote": vote_value}
            )

            if not created:
                if vote.vote == vote_value:
                    vote.delete()
                    return Response(
                        {"message": "Vote removed"}, status=status.HTTP_200_OK
                    )
                else:
                    vote.vote = vote_value
                    vote.save()

            serializer = self.get_serializer(vote)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError:
            return Response(
                {"error": "Database error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Unexpected error during post voting: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


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
        try:
            user = request.user
            comment_slug = self.kwargs["comment_slug"]
            vote_value = request.data.get("vote")

            comment = get_object_or_404(Comment, slug=comment_slug)

            vote, created = CommentVote.objects.get_or_create(
                user=user, comment=comment, defaults={"vote": vote_value}
            )

            if not created:
                if vote.vote == vote_value:
                    vote.delete()
                    return Response(
                        {"message": "Vote removed"}, status=status.HTTP_200_OK
                    )
                else:
                    vote.vote = vote_value
                    vote.save()

            serializer = self.get_serializer(vote)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError:
            return Response(
                {"error": "Database error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Unexpected error during post voting: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class CommentViewSet(viewsets.ModelViewSet):
    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    authentication_classes = [JWTAuthentication]
    lookup_field = "slug"

    def get_queryset(self):
        try:
            post_slug = self.kwargs.get("post_slug")
            if post_slug:
                post = get_object_or_404(Post, slug=post_slug)
                return Comment.objects.filter(post=post, is_deleted=False)
            return Comment.objects.filter(is_deleted=False)
        except DatabaseError:
            raise Exception("Database error while fetching comments.")

    def get_object(self):
        try:
            queryset = self.get_queryset()
            filter_kwargs = {self.lookup_field: self.kwargs["slug"]}
            obj = get_object_or_404(queryset, **filter_kwargs)
            self.check_object_permissions(self.request, obj)
            return obj
        except Http404:
            raise NotFound("The comment with this slug does not exist.")
        except DatabaseError:
            return Response(
                {"error": "Database error occurred while fetching comment."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Unexpected error: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

    def get_permissions(self):
        if self.request.method not in permissions.SAFE_METHODS:
            return [IsPostOrCommentOwnerOrAdmin()]
        return [AllowAny()]

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        try:
            post_slug = self.kwargs.get("post_slug")
            post = get_object_or_404(Post, slug=post_slug)

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save(user=request.user, post=post)

            comment_instance = serializer.instance
            handle_and_save_images(request, comment_instance, "images")

            headers = self.get_success_headers(serializer.data)
            return Response(
                serializer.data, status=status.HTTP_201_CREATED, headers=headers
            )
        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError:
            return Response(
                {"error": "Database error occurred while creating comment."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Unexpected error: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save(user=request.user)

            handle_and_save_images(request, instance, "images")

            return Response(serializer.data)
        except ValidationError as ve:
            return Response({"error": str(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError:
            return Response(
                {"error": "Database error occurred while updating comment."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Unexpected error: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

    @transaction.atomic
    def destroy(self, request, *args, **kwargs):
        try:
            comment = self.get_object()
            comment.is_deleted = True
            comment.save()
            return Response(
                {"message": "Comment deleted successfully"},
                status=status.HTTP_204_NO_CONTENT,
            )
        except DatabaseError:
            return Response(
                {"error": "Database error occurred while deleting comment."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            # Log the exception for debugging
            print(f"Unexpected error: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
