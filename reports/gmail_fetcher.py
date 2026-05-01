"""
Gmail API Fetcher — Pengganti IMAP
Menggunakan Gmail API (OAuth2) untuk fetch email laporan DMARC
"""

import os
import base64
import logging
from pathlib import Path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)

# Path ke credentials dan token
BASE_DIR = Path(__file__).resolve().parent.parent
TOKEN_PATH = BASE_DIR / 'token.json'
CREDENTIALS_PATH = BASE_DIR / 'credentials.json'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.modify']


def get_gmail_service():
    """
    Build Gmail API service dengan token yang sudah ada.
    Otomatis refresh token jika expired.
    """
    creds = None

    if TOKEN_PATH.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)

    # Refresh token jika expired
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open(TOKEN_PATH, 'w') as token:
            token.write(creds.to_json())

    if not creds or not creds.valid:
        raise Exception(
            "Token Gmail tidak valid. Jalankan generate_token.py lagi."
        )

    service = build('gmail', 'v1', credentials=creds)
    return service


def fetch_dmarc_emails(max_results: int = 50) -> list:
    """
    Fetch email laporan DMARC dari Gmail.
    Cari email yang punya attachment XML/gz/zip dan belum diproses.

    Return list of dict:
    {
        'message_id': str,
        'subject': str,
        'date': str,
        'attachments': [{'filename': str, 'data': bytes}]
    }
    """
    service = get_gmail_service()
    results = []

    try:
        # Cari email dengan attachment yang belum dibaca
        # Query Gmail: punya attachment, belum dibaca
        query = 'has:attachment is:unread'

        response = service.users().messages().list(
            userId='me',
            q=query,
            maxResults=max_results,
        ).execute()

        messages = response.get('messages', [])
        logger.info(f"Ditemukan {len(messages)} email belum dibaca dengan attachment")

        for msg in messages:
            msg_id = msg['id']

            # Ambil detail email
            msg_detail = service.users().messages().get(
                userId='me',
                id=msg_id,
                format='full',
            ).execute()

            # Ambil subject dan tanggal
            headers = msg_detail.get('payload', {}).get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
            date = next((h['value'] for h in headers if h['name'] == 'Date'), '')

            # Cari attachment XML/gz/zip
            attachments = []
            payload = msg_detail.get('payload', {})
            parts = payload.get('parts', [])

            for part in parts:
                filename = part.get('filename', '')
                if not filename:
                    continue

                filename_lower = filename.lower()
                if not any(filename_lower.endswith(ext) for ext in ['.xml', '.gz', '.zip']):
                    continue

                # Download attachment
                body = part.get('body', {})
                attachment_id = body.get('attachmentId')

                if attachment_id:
                    attachment = service.users().messages().attachments().get(
                        userId='me',
                        messageId=msg_id,
                        id=attachment_id,
                    ).execute()

                    data = base64.urlsafe_b64decode(attachment['data'])
                    attachments.append({
                        'filename': filename,
                        'data': data,
                    })
                elif body.get('data'):
                    data = base64.urlsafe_b64decode(body['data'])
                    attachments.append({
                        'filename': filename,
                        'data': data,
                    })

            if attachments:
                results.append({
                    'message_id': msg_id,
                    'subject': subject,
                    'date': date,
                    'attachments': attachments,
                })

                # Tandai email sebagai sudah dibaca
                service.users().messages().modify(
                    userId='me',
                    id=msg_id,
                    body={'removeLabelIds': ['UNREAD']},
                ).execute()

        return results

    except Exception as e:
        logger.error(f"Error fetch Gmail: {e}")
        raise