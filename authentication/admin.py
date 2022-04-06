from django.contrib import admin
from .models import User, URLCorsPermit

admin.site.register(User)
admin.site.register(URLCorsPermit)