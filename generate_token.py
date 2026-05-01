from google_auth_oauthlib.flow import InstalledAppFlow
 
# Scope: baca email + tandai sudah dibaca
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
]
 
flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
creds = flow.run_local_server(port=0)
 
with open('token.json', 'w') as token:
    token.write(creds.to_json())
 
print("✅ Token berhasil dibuat! File token.json sudah ada.")
print("Sekarang sistem bisa fetch email DMARC dari Gmail otomatis.")