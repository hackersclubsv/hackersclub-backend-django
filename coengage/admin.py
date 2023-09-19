from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import (
    Category,
    Comment,
    CommentVote,
    CustomUser,
    Group,
    Image,
    Post,
    PostVote,
    Tag,
)


class CustomUserAdmin(UserAdmin):
    list_display = ("username", "id", "email", "role")
    readonly_fields = ("id",)
    fieldsets = (
        ("User Info", {"fields": ("id", "username", "password")}),
        (
            ("Personal info"),
            {
                "fields": (
                    "first_name",
                    "last_name",
                    "email",
                    "is_verified",
                    "bio",
                    "profile_picture",
                    "role",
                )
            },
        ),
        (("Important dates"), {"fields": ("last_login", "date_joined")}),
        (
            ("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
    )


class PostAdmin(admin.ModelAdmin):
    list_display = ("title", "id", "user", "category", "number_of_images", "created_at")
    fields = [
        "title",
        "content",
        "slug",
        "tags",
        "user",
        "category",
        "is_deleted",
        "is_sticky",
    ]

    def number_of_images(self, obj):
        return obj.images.count()

    number_of_images.short_description = "Number of Images"


class ImageAdmin(admin.ModelAdmin):
    list_display = ("id", "url", "post", "comment")
    fields = ["url", "post", "comment"]


class CommentAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "content_short",
        "post",
        "user",
        "created_at",
        "updated_at",
        "is_deleted",
        "parent",
    )
    fields = [
        "content",
        "created_at",
        "updated_at",
        "user",
        "is_deleted",
        "post",
        "parent",
    ]

    def content_short(self, obj):
        return obj.content[:50]

    content_short.short_description = "Content"


class CategoryAdmin(admin.ModelAdmin):
    list_display = ("id", "name")
    fields = ["name"]


class TagAdmin(admin.ModelAdmin):
    list_display = ("id", "name")
    fields = ["name"]


class GroupAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "description", "created_at", "updated_at")
    fields = ["name", "description", "users"]


class PostVoteAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "post", "vote")
    fields = ["user", "post", "vote"]


class CommentVoteAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "comment", "vote")
    fields = ["user", "comment", "vote"]


admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Category, CategoryAdmin)
admin.site.register(Tag, TagAdmin)
admin.site.register(Post, PostAdmin)
admin.site.register(Comment, CommentAdmin)
admin.site.register(Image, ImageAdmin)
admin.site.register(Group, GroupAdmin)
admin.site.register(PostVote, PostVoteAdmin)
admin.site.register(CommentVote, CommentVoteAdmin)
