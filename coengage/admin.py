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

    def number_of_images(self, obj):
        return obj.images.count()

    number_of_images.short_description = "Number of Images"


class ImageAdmin(admin.ModelAdmin):
    list_display = ("url", "post", "comment")


class CommentAdmin(admin.ModelAdmin):
    list_display = ("content_short", "post", "user", "created_at")

    def content_short(self, obj):
        return obj.content[:50]

    content_short.short_description = "Content"


admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Tag)
admin.site.register(Post, PostAdmin)
admin.site.register(Comment, CommentAdmin)
admin.site.register(Image, ImageAdmin)
admin.site.register(PostVote)
admin.site.register(CommentVote)
admin.site.register(Group)
admin.site.register(Category)
