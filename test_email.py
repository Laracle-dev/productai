import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from backend
load_dotenv('/app/backend/.env')

def test_email_sending():
    """Test that email sending works with the current configuration"""
    # Get Mailtrap credentials from environment variables
    smtp_host = os.environ.get("MAILTRAP_HOST", "live.smtp.mailtrap.io")
    smtp_port = int(os.environ.get("MAILTRAP_PORT", 587))
    smtp_user = os.environ.get("MAILTRAP_USERNAME", "api")
    smtp_pass = os.environ.get("MAILTRAP_PASSWORD", "")
    from_email = os.environ.get("MAILTRAP_FROM_EMAIL", "no-reply@ryansbrainai.com")
    
    # Test email address - change this to a real email for testing
    test_email = "ryan@laracle.com"  # Use your own email for testing
    
    logging.info(f"Testing email sending to {test_email}")
    logging.info(f"Using SMTP server: {smtp_host}:{smtp_port}")
    logging.info(f"Using username: {smtp_user}")
    
    # Create the email
    message = MIMEMultipart()
    message["From"] = from_email
    message["To"] = test_email
    message["Subject"] = "Test Email from Ryan's Brain AI"
    
    # Create email body
    body = """
Hello,

This is a test email to verify that the email sending functionality is working correctly.

If you're receiving this email, it means the Mailtrap Live Email Delivery configuration is working.

Best regards,
Ryan's Brain AI Team
"""
    message.attach(MIMEText(body, "plain"))
    
    try:
        # Create a secure connection with the server
        logging.info("Connecting to SMTP server...")
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()  # Upgrade the connection to secure
        
        logging.info("Authenticating with SMTP server...")
        server.login(smtp_user, smtp_pass)
        
        # Add special headers for Mailtrap
        headers = {
            'X-Mailer': 'Ryan\'s Brain AI Test Mailer',
            'X-Send-From': from_email  # Header used by Mailtrap
        }
        
        for key, value in headers.items():
            message.add_header(key, value)
        
        # Send email
        logging.info(f"Sending test email using {smtp_user} as sender...")
        server.sendmail(smtp_user, test_email, message.as_string())
        server.quit()
        
        logging.info(f"Test email sent successfully to {test_email}")
        return True
    except Exception as e:
        logging.error(f"Failed to send test email: {str(e)}")
        return False

if __name__ == "__main__":
    test_email_sending()
