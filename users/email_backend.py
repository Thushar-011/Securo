"""
Custom email backend for development that prints emails to console in a readable format.
"""

from django.core.mail.backends.console import EmailBackend as ConsoleEmailBackend


class CustomConsoleEmailBackend(ConsoleEmailBackend):
    """
    Custom console backend that prints emails in a more readable format for development.
    """
    
    def write_message(self, message):
        """
        Override the write_message method to print email in a more readable format.
        """
        msg_str = message.message()
        print("\n" + "=" * 80)
        print("EMAIL SENT (Console Backend - Development)")
        print("=" * 80)
        print(f"TO: {', '.join(message.to)}")
        print(f"FROM: {message.from_email}")
        print(f"SUBJECT: {message.subject}")
        print("-" * 80)
        print(msg_str)
        print("=" * 80 + "\n")
