import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from accounts.models import User

@csrf_exempt
def telegram_webhook(request):
    data = json.loads(request.body)

    chat_id = data["message"]["chat"]["id"]
    text = data["message"]["text"]

    if text.startswith("/start"):
        # contoh sederhana: ambil user pertama (nanti diganti logic token)
        user = User.objects.first()

        if user:
            user.chat_id = chat_id
            user.save()

    return JsonResponse({"ok": True})