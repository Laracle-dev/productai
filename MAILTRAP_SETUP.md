# Setting up Mailtrap for 2FA Emails

This AI Chatbot application uses Mailtrap.io for sending 2FA authentication emails during development and testing. Follow these instructions to set up Mailtrap for your deployment.

## What is Mailtrap?

Mailtrap is an email testing tool that allows you to capture and inspect emails sent from your application without delivering them to real recipients. This is ideal for testing email functionality in non-production environments.

## Setup Instructions

### 1. Create a Mailtrap Account

1. Go to [Mailtrap.io](https://mailtrap.io/) and sign up for an account
2. After signing in, navigate to your inbox (create a new one if needed)

### 2. Get Your SMTP Credentials

1. In your Mailtrap inbox, click on the "SMTP Settings" tab
2. You'll see your SMTP credentials including:
   - Host: smtp.mailtrap.io
   - Port: 2525 (or 587, 465 for SSL)
   - Username: (provided by Mailtrap)
   - Password: (provided by Mailtrap)

### 3. Configure Your Application

#### Local Development

1. Open your `/app/backend/.env` file
2. Update the Mailtrap configuration with your credentials:
   ```
   MAILTRAP_HOST="smtp.mailtrap.io"
   MAILTRAP_PORT="2525"
   MAILTRAP_USERNAME="your_mailtrap_username"
   MAILTRAP_PASSWORD="your_mailtrap_password"
   ```
3. Restart your backend server

#### Production Deployment

When deploying to DigitalOcean or another production environment, add these same environment variables to your deployment configuration.

For DigitalOcean App Platform:
1. Go to your app settings
2. Navigate to the "Environment Variables" section
3. Add the four Mailtrap variables

## Testing the Integration

1. Attempt to log in to the admin panel
2. Check your Mailtrap inbox - you should see the 2FA verification email
3. Use the code from the email to complete the authentication

## Moving to Production

When ready to use real email delivery in production:

1. Replace the Mailtrap credentials with your production email service
2. Update the environment variables with your production SMTP details:
   ```
   MAILTRAP_HOST="your.smtp.server"
   MAILTRAP_PORT="587"  # or appropriate port
   MAILTRAP_USERNAME="your_smtp_username"
   MAILTRAP_PASSWORD="your_smtp_password"
   ```

## Troubleshooting

If emails are not appearing in your Mailtrap inbox:

1. Verify your Mailtrap credentials are correctly entered in the .env file
2. Check the application logs for any SMTP errors
3. Ensure your network allows outbound connections on port 2525 (or your configured port)
4. If using the fallback method, check the application logs for simulated emails

For continued issues, visit the [Mailtrap Help Center](https://help.mailtrap.io/)
