from django.contrib import admin

from .models import Comment, CustomUser, Group, Post, Tag

admin.site.register(CustomUser)
admin.site.register(Tag)
admin.site.register(Post)
admin.site.register(Comment)
admin.site.register(Group)
