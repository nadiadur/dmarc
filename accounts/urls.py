from django.urls import path
from .views import PasswordResetConfirmView, PasswordResetRequestView, RegisterView, LoginView, LogoutView, UserDetailView, DashboardView, UserListView, ProfileView, ChangePasswordView
from .telegram_views import telegram_webhook

urlpatterns = [
    # User route
    path("login/", LoginView.as_view(), name="user_login"),
    path("register/", RegisterView.as_view(), name="register"),

    path("admin1/login/", LoginView.as_view(), name="admin_login"),

    path("admin-dashboard/", DashboardView.as_view()),
    path("logout/", LogoutView.as_view(), name="logout"),
    
    path("telegram/webhook/", telegram_webhook),

    path('users/', UserListView.as_view()),

   
    path("profile/", ProfileView.as_view()),
    path("change-password/", ChangePasswordView.as_view()),
    path("users/<str:id>/", UserDetailView.as_view()),

    path("password-reset/", PasswordResetRequestView.as_view()),
    path("password-reset-confirm/", PasswordResetConfirmView.as_view()),
]
