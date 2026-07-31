using System.Net;
using System.Text.Encodings.Web;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Identity;
using MimeKit;
using Soteria.Data;

namespace Soteria.Components.Account.Email;

public sealed class EmailSender(
    EmailOptions options)
    : IEmailSender<ApplicationUser>
{
    public Task SendConfirmationLinkAsync(
        ApplicationUser user,
        string email,
        string confirmationLink)
    {
        return SendLinkEmailAsync(
            email,
            "Confirm your email",
            "Confirm your Soteria account",
            "Please confirm your email address by selecting the link below.",
            "Confirm email",
            confirmationLink);
    }

    public Task SendPasswordResetLinkAsync(
        ApplicationUser user,
        string email,
        string resetLink)
    {
        return SendLinkEmailAsync(
            email,
            "Reset your password",
            "Reset your Soteria password",
            "A password reset was requested for your Soteria account. Select the link below to choose a new password.",
            "Reset password",
            resetLink);
    }

    public Task SendPasswordResetCodeAsync(
        ApplicationUser user,
        string email,
        string resetCode)
    {
        var encodedResetCode = HtmlEncoder.Default.Encode(resetCode);

        return SendEmailAsync(
            email,
            "Reset your password",
            $"""
             Reset your Soteria password

             Use the following code to reset your password:

             {resetCode}

             If you did not request a password reset, you can ignore this email.
             """,
            $"""
             <!DOCTYPE html>
             <html lang="en">
             <head>
                 <meta charset="utf-8">
                 <meta name="viewport" content="width=device-width, initial-scale=1">
                 <title>Reset your password</title>
             </head>
             <body>
                 <h1>Reset your Soteria password</h1>
                 <p>Use the following code to reset your password:</p>
                 <p><strong>{encodedResetCode}</strong></p>
                 <p>If you did not request a password reset, you can ignore this email.</p>
             </body>
             </html>
             """);
    }

    private Task SendLinkEmailAsync(
        string email,
        string subject,
        string heading,
        string message,
        string actionText,
        string encodedLink)
    {
        var plainTextLink = WebUtility.HtmlDecode(encodedLink);

        return SendEmailAsync(
            email,
            subject,
            $"""
             {heading}

             {message}

             {plainTextLink}

             If you did not request this action, you can ignore this email.
             """,
            $"""
             <!DOCTYPE html>
             <html lang="en">
             <head>
                 <meta charset="utf-8">
                 <meta name="viewport" content="width=device-width, initial-scale=1">
                 <title>{heading}</title>
             </head>
             <body>
                 <h1>{heading}</h1>
                 <p>{message}</p>
                 <p><a href="{encodedLink}">{actionText}</a></p>
                 <p>If you did not request this action, you can ignore this email.</p>
             </body>
             </html>
             """);
    }

    private async Task SendEmailAsync(
        string email,
        string subject,
        string textBody,
        string htmlBody)
    {
        var message = new MimeMessage
        {
            Subject = subject,
            Body = new BodyBuilder
            {
                TextBody = textBody,
                HtmlBody = htmlBody
            }.ToMessageBody()
        };

        message.From.Add(new MailboxAddress(
            options.DisplayName.Trim(),
            options.SenderAddress.Trim()));

        message.To.Add(MailboxAddress.Parse(email));

        using var client = new SmtpClient();

        await client.ConnectAsync(
            options.Host.Trim(),
            options.Port,
            GetSecureSocketOptions(options.Security));

        await client.AuthenticateAsync(
            options.Username.Trim(),
            options.Password);

        await client.SendAsync(message);
        await client.DisconnectAsync(quit: true);
    }

    private static SecureSocketOptions GetSecureSocketOptions(
        EmailSecurity security)
    {
        return security switch
        {
            EmailSecurity.SslOnConnect => SecureSocketOptions.SslOnConnect,
            EmailSecurity.StartTls => SecureSocketOptions.StartTls,
            _ => throw new InvalidOperationException(
                $"The configured email security mode '{security}' is not supported.")
        };
    }
}