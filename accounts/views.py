from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password

from .models import User
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