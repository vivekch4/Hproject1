
from twilio.rest import Client


def send_sms(phone_number, message_text):
    account_sid = "ACd7994a397edfc86cb7966dd4178c6815"  # Your Twilio Account SID
    
    auth_token = "b7080acb53c632d8f21ebb1f60523300"  # Your Auth Token

    client = Client(account_sid, auth_token)

    message = client.messages.create(
        body=message_text,
        from_="+19515403815",  # Your Twilio number
        to=phone_number,
    )

    print(f"Message sent! SID: {message.sid}")
