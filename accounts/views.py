import uuid
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from django.utils import timezone

from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from reports.models import DMARCReport
from .models import User, PasswordResetToken
from .serializers import RegisterSerializer, LoginSerializer


class RegisterView(APIView):
    permission_classes = [AllowAny] 

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                "message": "Register berhasil",
                "user_id": user.user_id,
                "email": user.email,
                "role": user.role
            }, status=201)
        return Response(serializer.errors, status=400)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "Login berhasil",
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "email": user.email,
                "name": user.name,
                "user_id": user.user_id,
                "role": user.role
            })
        return Response(serializer.errors, status=400)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logout berhasil"})
        except Exception:
            return Response({"error": "Token tidak valid"}, status=400)


class AdminLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            if user.role != "admin":
                return Response({"detail": "Bukan admin"}, status=403)
            refresh = RefreshToken.for_user(user)
            return Response({
                "message": "Login berhasil",
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "email": user.email,
                "user_id": user.user_id,
                "role": user.role
            })
        return Response(serializer.errors, status=400)


class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != "admin":
            return Response({"detail": "Unauthorized"}, status=403)

        users = User.objects.all().values(
            "user_id", "name", "email", "role"
        )
        return Response(list(users))


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        user = request.user
        user.name = request.data.get("name", user.name)
        user.email = request.data.get("email", user.email)
        user.save()
        return Response({
            "message": "Profile updated",
            "name": user.name,
            "email": user.email
        })


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if not user.check_password(old_password):
            return Response({"detail": "Password lama salah"}, status=400)

        user.set_password(new_password)
        user.save()
        return Response({"message": "Password updated"})


class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        if request.user.role != "admin":
            return Response({"detail": "Unauthorized"}, status=403)

        try:
            user = User.objects.get(user_id=id)
        except User.DoesNotExist:
            return Response({"detail": "User tidak ditemukan"}, status=404)

        return Response({
            "user_id": user.user_id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
        })

    def patch(self, request, id):
        if request.user.role != "admin":
            return Response({"detail": "Unauthorized"}, status=403)

        try:
            user = User.objects.get(user_id=id)
        except User.DoesNotExist:
            return Response({"detail": "User tidak ditemukan"}, status=404)

        user.name = request.data.get("name", user.name)
        user.email = request.data.get("email", user.email)
        user.role = request.data.get("role", user.role)

        # ✅ FIX: hash password sebelum disimpan
        password = request.data.get("password")
        if password:
            user.set_password(password)

        user.save()
        return Response({"message": "User updated"})

    def delete(self, request, id):
        if request.user.role != "admin":
            return Response({"detail": "Unauthorized"}, status=403)

        try:
            user = User.objects.get(user_id=id)
        except User.DoesNotExist:
            return Response({"detail": "User tidak ditemukan"}, status=404)

        user.delete()
        return Response({"message": "User deleted"})


class PasswordResetRequestView(APIView):
    """POST /api/auth/password-reset/ — kirim link reset ke email"""
    permission_classes = [AllowAny]
 
    def post(self, request):
        email = request.data.get("email")
 
        if not email:
            return Response({"detail": "Email wajib diisi."}, status=400)
 
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            # Jangan beritahu apakah email terdaftar (keamanan)
            return Response({"message": "Jika email terdaftar, link reset akan dikirim."})
 
        # Hapus token lama milik user ini
        PasswordResetToken.objects.filter(user=user).delete()
 
        # Buat token baru, berlaku 1 jam
        token = PasswordResetToken.objects.create(
            user=user,
            token=str(uuid.uuid4()),
            expires_at=timezone.now() + timedelta(hours=1),
        )
 
        reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token.token}"
 
        send_mail(
            subject="Reset Password - Dmarclytics",
            message=(
                f"Halo {user.name},\n\n"
                f"Klik link berikut untuk mereset password Anda:\n{reset_link}\n\n"
                f"Link berlaku selama 1 jam.\n\n"
                f"Jika Anda tidak merasa meminta reset password, abaikan email ini."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
 
        return Response({"message": "Jika email terdaftar, link reset akan dikirim."})
 
 
class PasswordResetConfirmView(APIView):
    """POST /api/auth/password-reset-confirm/ — simpan password baru"""
    permission_classes = [AllowAny]
 
    def post(self, request):
        token_str = request.data.get("token")
        new_password = request.data.get("new_password")
 
        if not token_str or not new_password:
            return Response({"detail": "Token dan password baru wajib diisi."}, status=400)
 
        if len(new_password) < 8:
            return Response({"detail": "Password minimal 8 karakter."}, status=400)
 
        try:
            token = PasswordResetToken.objects.get(token=token_str)
        except PasswordResetToken.DoesNotExist:
            return Response({"detail": "Token tidak valid."}, status=400)
 
        if token.expires_at < timezone.now():
            token.delete()
            return Response({"detail": "Token sudah kadaluarsa. Silakan minta reset ulang."}, status=400)
 
        user = token.user
        user.set_password(new_password)
        user.save()
 
        # Hapus token setelah dipakai
        token.delete()
 
        return Response({"message": "Password berhasil direset. Silakan login."})
 
class DashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != "admin":
            return Response({"detail": "Unauthorized"}, status=403)

        total_users = User.objects.count()

        total_admin = User.objects.filter(role="admin").count()

        total_regular_users = User.objects.filter(role="user").count()

        today_users = User.objects.filter(
            created_at__date=timezone.now().date()
        ).count()

        recent_users = User.objects.order_by("-created_at")[:8]

        return Response({
            "total_users": total_users,
            "total_admin": total_admin,
            "total_regular_users": total_regular_users,
            "today_users": today_users,

            "recent_users": [
                {
                    "id": u.id,
                    "user_id": u.user_id,
                    "name": u.name,
                    "email": u.email,
                    "role": u.role,
                    "created_at": u.created_at,
                }
                for u in recent_users
            ]
        })