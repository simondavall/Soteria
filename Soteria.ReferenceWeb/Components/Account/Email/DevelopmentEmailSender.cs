using System.Net;
using Microsoft.AspNetCore.Identity;
using Soteria.ReferenceWeb.Data;

namespace Soteria.ReferenceWeb.Components.Account.Email;

public sealed class DevelopmentEmailSender(
    ILogger<DevelopmentEmailSender> logger)
    : IEmailSender<ApplicationUser>
{
    public Task SendConfirmationLinkAsync(
        ApplicationUser user,
        string email,
        string confirmationLink)
    {
        LogEmail(
            email,
            "Confirm your email",
            "Confirm your account by opening the following link:",
            WebUtility.HtmlDecode(confirmationLink));

        return Task.CompletedTask;
    }

    public Task SendPasswordResetLinkAsync(
        ApplicationUser user,
        string email,
        string resetLink)
    {
        LogEmail(
            email,
            "Reset your password",
            "Reset your password by opening the following link:",
            WebUtility.HtmlDecode(resetLink));

        return Task.CompletedTask;
    }

    public Task SendPasswordResetCodeAsync(
        ApplicationUser user,
        string email,
        string resetCode)
    {
        LogEmail(
            email,
            "Reset your password",
            "Use the following code to reset your password:",
            resetCode);

        return Task.CompletedTask;
    }

    private void LogEmail(
        string email,
        string subject,
        string message,
        string action)
    {
        logger.LogInformation(
            """

            ============================================================
            DEVELOPMENT REFERENCE WEB IDENTITY EMAIL
            ============================================================
            To: {Email}
            Subject: {Subject}

            {Message}

            {Action}
            ============================================================

            """,
            email,
            subject,
            message,
            action);
    }
}