from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from coengage.models import Category, Comment, CommentVote, Image, Post, PostVote, Tag

from .utilities import generate_otp, normalize_name

User = get_user_model()


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token["username"] = user.username
        token["email"] = user.email

        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        if not self.user.is_verified:
            raise serializers.ValidationError(
                [
                    {
                        "error": "Email is not verified",
                        "message": "Email is not verified, Please verify the email to login",
                    }
                ]
            )

        return data


class URLImageField(serializers.ImageField):
    def to_representation(self, value):
        return value


class UserSerializer(serializers.ModelSerializer):
    profile_picture = URLImageField(use_url=True, required=False)
    email = serializers.EmailField(read_only=True)

    def validate_email(self, value):
        value = value.strip().lower()
        if not value.endswith("@northeastern.edu"):
            raise serializers.ValidationError(
                "Email must be from the northeastern.edu domain"
            )
        return value

    class Meta:
        model = User
        fields = ["username", "id", "email", "bio", "profile_picture"]


class RegisterSerializer(UserSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    class Meta(UserSerializer.Meta):
        fields = ["username", "email", "password"]

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data.get("password"))
        validated_data["otp"] = generate_otp()
        validated_data["otp_created_at"] = timezone.now()
        validated_data["otp_expiration"] = timezone.now() + timedelta(minutes=10)
        validated_data["otp_attempts"] = 0
        validated_data["otp_attempts_timestamp"] = None
        return super().create(validated_data)


class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class VerifyEmailSerializer(serializers.Serializer):
    otp = serializers.IntegerField(required=True)
    email = serializers.EmailField(required=True)


class RequestPasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)


class PasswordResetSerializer(serializers.Serializer):
    otp = serializers.IntegerField(required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = "__all__"


class URLPostImageField(serializers.ImageField):
    def to_representation(self, value):
        return value.url


class PostSerializer(serializers.ModelSerializer):
    title = serializers.CharField(required=True)
    content = serializers.CharField(required=True)
    author = serializers.CharField(source="user.username", read_only=True)
    images = serializers.SerializerMethodField()
    category_name = serializers.CharField(write_only=True, required=False)
    input_tags = serializers.ListField(
        child=serializers.CharField(), required=False, write_only=True
    )
    tags = serializers.SerializerMethodField()
    upvotes = serializers.SerializerMethodField()
    downvotes = serializers.SerializerMethodField()
    user_vote = serializers.SerializerMethodField()
    total_comments = serializers.IntegerField(read_only=True)
    category_display = serializers.SerializerMethodField()

    def get_upvotes(self, obj):
        return PostVote.objects.filter(post=obj, vote=PostVote.UPVOTE).count()

    def get_downvotes(self, obj):
        return PostVote.objects.filter(post=obj, vote=PostVote.DOWNVOTE).count()

    def get_user_vote(self, obj):
        user = self.context["request"].user
        if user.is_authenticated:
            vote = PostVote.objects.filter(post=obj, user=user).first()
            return vote.vote if vote else None
        return None

    def handle_tags(self, instance, tags_data):
        instance.tags.clear()
        for tag_name in tags_data:
            tag_name = normalize_name(tag_name)
            tag, _ = Tag.objects.get_or_create(name=tag_name)
            instance.tags.add(tag)

    def handle_category(self, validated_data):
        if category_name := validated_data.pop("category_name", None):
            category_name = normalize_name(category_name)
            category, _ = Category.objects.get_or_create(name=category_name)
            validated_data["category"] = category

    def get_category_display(self, obj):
        return obj.category.name if obj.category else None

    def create(self, validated_data):
        tags_data = validated_data.pop("input_tags", [])

        self.handle_category(validated_data)
        post = Post.objects.create(**validated_data)
        self.handle_tags(post, tags_data)

        return post

    def update(self, instance, validated_data):
        tags_data = validated_data.pop("input_tags", None)

        self.handle_category(validated_data)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if tags_data is not None:
            self.handle_tags(instance, tags_data)
        return instance

    def get_images(self, obj):
        return [image.url for image in obj.images.all()]

    def get_tags(self, obj):
        return [tag.name for tag in obj.tags.all()]

    class Meta:
        model = Post
        fields = [
            "id",
            "title",
            "content",
            "category_name",
            "category_display",
            "input_tags",
            "tags",
            "images",
            "slug",
            "created_at",
            "updated_at",
            "is_deleted",
            "is_sticky",
            "author",
            "upvotes",
            "downvotes",
            "user_vote",
            "total_comments",
        ]

        read_only_fields = [
            "slug",
            "created_at",
            "updated_at",
            "is_deleted",
            "is_sticky",
            "user",
            "images",
            "upvotes",
            "downvotes",
            "user_vote",
            "total_comments",
        ]


class PostVoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = PostVote
        fields = "__all__"


class CommentVoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = CommentVote
        fields = "__all__"


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = "__all__"


class CommentSerializer(serializers.ModelSerializer):
    user = serializers.ReadOnlyField(source="user.username")
    images = serializers.SerializerMethodField()
    upvotes = serializers.SerializerMethodField()
    downvotes = serializers.SerializerMethodField()
    user_vote = serializers.SerializerMethodField()

    def get_upvotes(self, obj):
        return CommentVote.objects.filter(comment=obj, vote=CommentVote.UPVOTE).count()

    def get_downvotes(self, obj):
        return CommentVote.objects.filter(
            comment=obj, vote=CommentVote.DOWNVOTE
        ).count()

    def get_user_vote(self, obj):
        user = self.context["request"].user
        if user.is_authenticated:
            vote = CommentVote.objects.filter(comment=obj, user=user).first()
            return vote.vote if vote else None
        return None

    def get_images(self, obj):
        return [image.url for image in obj.images.all()]

    class Meta:
        model = Comment
        fields = [
            "id",
            "content",
            "user",
            "post",
            "parent",
            "created_at",
            "updated_at",
            "is_deleted",
            "images",
            "upvotes",
            "downvotes",
            "user_vote",
        ]
        read_only_fields = [
            "created_at",
            "updated_at",
            "user",
            "images",
            "upvotes",
            "downvotes",
            "user_vote",
        ]
