import os
import django 
# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hackersclub_backend.settings')
django.setup()

import random
from faker import Faker
from coengage.models import Category, Post, Comment, CustomUser, Tag

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'hackersclub_backend.settings')
django.setup()

fake = Faker()

categories = ['Campus Life', 'Job Hunting', 'Tech Dojo']
tags = ['Python', 'React', 'JavaScript', 'ML', 'AI', 'Silicon Valley', 'Seattle', 'Boston',
        'San Francisco', 'INFO5100', 'ENCP6000', 'INFO6105', 'Hackathon', 'Algorithm', 'Java']


# Creating categories
for category_name in categories:
    Category.objects.get_or_create(name=category_name)

# Creating tags
for tag_name in tags:
    Tag.objects.get_or_create(name=tag_name)


# Creating users
for _ in range(20):
    user_email = fake.email()
    user_name = fake.user_name()
    CustomUser.objects.get_or_create(email=user_email, username=user_name, is_verified=True, otp="123456")

# Creating 200 random posts
for _ in range(200):
    random_user = random.choice(CustomUser.objects.all())
    random_category = random.choice(Category.objects.all())
    random_tags = random.sample(list(Tag.objects.all()), k=random.randint(1, 3)) # random.randint is inclusive

    post = Post.objects.create(
        title=fake.sentence(),
        content=fake.text(),
        user=random_user,
        category=random_category,
    )

    post.tags.set(random_tags)
    post.save()

# Generating random comments for each post
for post in Post.objects.all():
    for _ in range(random.randint(0, 10)):
        comment_user = random.choice(CustomUser.objects.all())
        Comment.objects.create(
            content=fake.sentence(),
            post=post,
            user=comment_user,
        )

# Generating child comments (replies to root comments)
for comment in Comment.objects.filter(parent__isnull=True).all():
    if random.randint(1, 4) == 1:  # 1 in 10 chance of having replies
        for _ in range(random.randint(0, 5)):  # can have up to 3 replies
            reply_user = random.choice(CustomUser.objects.all())
            Comment.objects.create(
                content=fake.sentence(),
                post=comment.post,
                parent=comment,
                user=reply_user,
            )
      
print("20 random users, 200 random posts, and related comments created!")
