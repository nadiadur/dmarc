from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
]

flow = InstalledAppFlow.from_client_secrets_file(
    'credentials.json',
    SCOPES,
    redirect_uri='urn:ietf:wg:oauth:2.0:oob'
)

auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline')

print("\n Buka URL ini di browser:\n")
print(auth_url)
print("\nSetelah login, paste kode di sini:")
code = input("Kode: ")

flow.fetch_token(code=code)
creds = flow.credentials

with open('token.json', 'w') as f:
    f.write(creds.to_json())

print("Token berhasil dibuat!")
