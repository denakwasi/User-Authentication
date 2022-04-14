from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
# 
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
User = get_user_model()

@api_view(['GET'])
@permission_classes([AllowAny])
def get_tokens_for_user(request):

    # find the user base in params
    user = User.objects.first()

    refresh = RefreshToken.for_user(user)

    return Response({ 
       'refresh': str(refresh),
      #  'access': str(refresh.access_token),
    })
   

schema_view = get_schema_view(
   openapi.Info(
      title="Authentication API",
      default_version='v1',
      description="Authentication API system",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)



urlpatterns = [
   path('admin/', admin.site.urls),
   path('auth/', include('authentication.urls')),
   path('auth/', include('djoser.urls.jwt')),
   # path('auth/token/', TokenObtainPairView.as_view(), name='token'),
   # path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
   # 
   path('auth/token/', get_tokens_for_user, name='token'),
   path('auth/refresh/', get_tokens_for_user, name='refresh'),

   # Swagger docs
   path('swagger/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
   path('auth/docs/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
   path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)  
