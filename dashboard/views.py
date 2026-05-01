from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from accounts.models import User
from reports.models import DMARCReport, AlertLog


class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # hanya admin
        if request.user.role != "admin":
            return Response({"detail": "Unauthorized"}, status=403)

        data = {
            "total_users": User.objects.count(),
            "total_reports": DMARCReport.objects.count(),
            "total_issues": AlertLog.objects.filter(status="failed").count()
        }

        return Response(data)