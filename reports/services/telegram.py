import requests

BOT_TOKEN = "8660010524:AAHboLKYLGv1nuF-tl3E76iYvYNUKN-eJ8w"

def send_telegram(chat_id, message):
    url = "https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage"

    res = requests.post(url, data={
        "chat_id": chat_id,
        "text": message
    })

    print(res.status_code)
    print(res.json())

    return res.json()