from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
    path('signup/', views.UserCreationView.as_view(), name='sign_up'),
    path('users/', views.Users.as_view(), name='users'),
    path('update-user/<str:user_id>/', views.UpdateUser.as_view(), name='update_user'),
    path('delete-user/<str:user_id>/', views.DeleteUser.as_view(), name='delete_user'),
    path('verify-email/', views.VerifyEmail.as_view(), name='verify_email'),
    path('change-password/', views.UserChangePasswordView.as_view(), name='change_password'),
    path('reset-password-email/', views.SendPasswordResetEmail.as_view(), name='reset_password_email'),
    path('reset-password/<uid>/<token>/', views.ResetPasswordView.as_view(), name='reset_password'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)