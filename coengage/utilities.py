import random

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from django.conf import settings


def generate_otp():
    return str(random.randint(100000, 999999))


def send_email_ses(username, otp, email):
    ses = boto3.client("ses", region_name=settings.AWS_SES_REGION_NAME)
    try:
        response = ses.send_email(
            Destination={
                "ToAddresses": [email],
            },
            Message={
                "Body": {
                    "Html": {
                        "Charset": "UTF-8",
                        "Data": f"""
                            <p>Hello {username},</p>
                            <p>You requested a one-time password. Use this password to continue your process.</p>
                            <table width='100%'><tr><td style='text-align: center; font-size: 28px; font-weight: bold;'>{otp}</td></tr></table>
                            <p>If you didn't request this email, please ignore it.</p>
                            <p>-- Northeastern University Silicon Valley HackersClub</p>
                        """,
                    },
                },
                "Subject": {
                    "Charset": "UTF-8",
                    "Data": "Your one-time password",
                },
            },
            Source="vidyalathanataraja.r@northeastern.edu",
        )
    except (BotoCoreError, ClientError) as error:
        return {"success": False, "message": str(error)}
    else:
        return {"success": True, "message": response["MessageId"]}
