from smtplib import SMTP_SSL, SMTP_SSL_PORT, SMTP, SMTP_PORT
from email.message import EmailMessage

import logging

logging.basicConfig(filename='imap_tools.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s',
                    level='DEBUG')

# Craft the email using email.message.EmailMessage
from_email = 'My name <someone@examples.com>'  # or simply the email address
to_emails = ['address@example.org', 'admin@devdungeon.com']
email_message = EmailMessage()
email_message.add_header('To', ', '.join(to_emails))
email_message.add_header('From', from_email)
email_message.add_header('Subject', 'Hello!')
email_message.add_header('X-Priority', '1')  # Urgency, 1 highest, 5 lowest
email_message.set_content('Hello, world!')

# Connect, authenticate, and send mail
smtp_server = SMTP_SSL('localhost', port=SMTP_SSL_PORT)

smtp_server = SMTP('localhost', port=SMTP_PORT)

smtp_server.set_debuglevel(1)  # Show SMTP server interactions
smtp_server.login('user@example.com', 'pass')
smtp_server.sendmail(from_email, to_emails, email_message.as_bytes())

# Disconnect
smtp_server.quit()