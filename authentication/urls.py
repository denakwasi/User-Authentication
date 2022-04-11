from django.urls import path
from . import views

urlpatterns = [
    path('signup/', views.UserCreationView.as_view(), name='sign_up'),
    path('users/', views.Users.as_view(), name='users'),
    # path('user/<str:user_id>/', views.User.as_view(), name='user'),
    path('user-update/<str:user_id>/', views.UpdateUser.as_view(), name='update_user'),
    path('user-delete/<str:user_id>/', views.DeleteUser.as_view(), name='delete_user'),
    path('verified/', views.VerifyEmail.as_view(), name='verify_email'),
    path('user-change-password/', views.UserChangePasswordView.as_view(), name='change_password'),
    path('user-reset-password-email/', views.SendPasswordResetEmail.as_view(), name='reset_password_email'),
    path('user-reset-password/', views.ResetPasswordView.as_view(), name='reset_password'),
    # path('cors-permit-url/', views.URLCorsPermitView.as_view(), name='cors_permit_url'),
    # path('cors-permit-url/<url_id>/', views.UpdateOrDeleteURLCorsPermitView.as_view(), name='cors_permit_url_update_or_delete'),
    path('make-user-admin/<str:admin_to_be_id>/', views.MakeUserAdmin.as_view(), name='make_user_admin'),
    path('make-user-nonadmin/<str:admin_id>/', views.MakeUserNonAdmin.as_view(), name='make_user_nonadmin'),
] 