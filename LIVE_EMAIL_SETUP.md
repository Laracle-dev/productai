# Setting up Live Email Delivery with Mailtrap

This AI Chatbot application is now configured to use Mailtrap's live email delivery service for sending real 2FA authentication emails to users. Follow these instructions to ensure proper setup.

## What is Mailtrap Live Email Delivery?

Mailtrap Live Email Delivery is a service that allows sending real emails to recipients, unlike the testing inbox which captures emails for testing. This is ideal for production environments where you need to deliver actual emails to users.

## Current Configuration

The application has been configured to use Mailtrap's live email delivery service with the following settings:

- Host: `live.smtp.mailtrap.io`
- Port: `587` (with TLS)
- Username: `api`
- Password: [needs to be configured]
- From Email: `notifications@ryansbrainai.com`

## Required Setup

1. **Add Your Actual Mailtrap Password**

   You need to replace the placeholder password in the `.env` file with your actual Mailtrap API token (without the **** obfuscation).

   Open the file `/app/backend/.env` and update the following line:
   ```
   MAILTRAP_PASSWORD="your-actual-mailtrap-password-here"  # Replace with your full unobfuscated password
   ```

2. **Restart the Backend Server**

   After updating the password, restart the backend server to apply the changes:
   ```
   sudo supervisorctl restart backend
   ```

3. **Verify the Email Configuration**

   Run the test email script to verify that the email sending works:
   ```
   python /app/test_email.py
   ```

   If the test is successful, you should see a message confirming that the email was sent, and the recipient should receive the test email.

## Sending Domains Setup (Optional)

For better deliverability, you may want to set up a sending domain in your Mailtrap account:

1. Log in to your Mailtrap account
2. Go to Email Sending → Sending Domains
3. Add and verify your domain
4. Update the `MAILTRAP_FROM_EMAIL` in your `.env` file to use your verified domain

## Troubleshooting

If you encounter issues:

1. **Authentication Errors**:
   - Ensure you're using the full, unobfuscated password/token
   - Verify your Mailtrap account is active and in good standing

2. **Email Not Delivered**:
   - Check your Mailtrap dashboard for error messages
   - Verify the recipient email address is valid
   - Check the application logs for SMTP errors
   - Ensure your Mailtrap account has email sending credits

3. **Server Connection Issues**:
   - Verify that your network allows outbound connections on port 587
   - Check if your firewall is blocking SMTP connections

## Moving to Production

When deploying to production:

1. Update the `.env` file or environment variables on your hosting platform
2. Consider using environment variables or a secret management system for the sensitive credentials
3. Monitor your email sending quota and deliverability in the Mailtrap dashboard

For additional help, consult the [Mailtrap Documentation](https://mailtrap.io/blog/category/email-sending/) or contact Mailtrap support.
