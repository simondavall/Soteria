using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Soteria.Data;

namespace Soteria.Components.Account.Pages;

public partial class ForgotPassword
{
    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private IEmailSender<ApplicationUser> EmailSender { get; set; } = null!;
    [Inject] private NavigationManager NavigationManager { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;

    [SupplyParameterFromForm] private InputModel? Input { get; set; }

    protected override void OnInitialized()
    {
        Input ??= new InputModel();
    }

    private async Task OnValidSubmitAsync()
    {
        var user = await UserManager.FindByEmailAsync(Input!.Email);
        if (user is null || !await UserManager.IsEmailConfirmedAsync(user))
        {
            // Don't reveal that the user doesn't exist or isn't confirmed.
            RedirectManager.RedirectTo("Account/ForgotPasswordConfirmation");
            return;
        }

        var code = await UserManager.GeneratePasswordResetTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var callbackUrl =
            NavigationManager.GetUriWithQueryParameters(
                NavigationManager
                    .ToAbsoluteUri("Account/ResetPassword")
                    .AbsoluteUri,
                new Dictionary<string, object?>
                {
                    ["code"] = code
                });

        await EmailSender.SendPasswordResetLinkAsync(user, Input.Email, HtmlEncoder.Default.Encode(callbackUrl));
        RedirectManager.RedirectTo("Account/ForgotPasswordConfirmation");
    }

    private sealed class InputModel
    {
        [Required] [EmailAddress] public string Email { get; set; } = string.Empty;
    }
}