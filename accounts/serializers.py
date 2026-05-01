from rest_framework import serializers
from .models import User


# ================= REGISTER =================
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["user_id", "name", "email", "password"]
        read_only_fields = ["user_id"]

    def create(self, validated_data):
        password = validated_data.pop("password")

        user = User.objects.create_user(
            password=password,
            **validated_data
        )

        return user


class LoginSerializer(serializers.Serializer):
    name = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        name = data.get("name")
        password = data.get("password")

        # 🔥 cari user berdasarkan name
        user = User.objects.filter(name=name).first()

        if not user:
            raise serializers.ValidationError("User tidak ditemukan")

        # 🔥 cek password
        if not user.check_password(password):
            raise serializers.ValidationError("Password salah")

        if not user.is_active:
            raise serializers.ValidationError("Akun tidak aktif")

        data["user"] = user
        return data