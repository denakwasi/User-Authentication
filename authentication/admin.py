from django.contrib import admin
from .models import User, AccessTokenExp

admin.site.register(User)
admin.site.register(AccessTokenExp)