using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Soteria.Data;

namespace Soteria.Components.Account.Pages;

public partial class ResendEmailConfirmation
{
    private const string ConfirmationMessage = "Verification email sent. Please check your email.";
    private string? _message;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private IEmailSender<ApplicationUser> EmailSender { get; set; } = null!;
    [Inject] private NavigationManager NavigationManager { get; set; } = null!;

    [SupplyParameterFromForm] private InputModel? Input { get; set; }

    protected override void OnInitialized()
    {
        Input ??= new InputModel();
    }

    private async Task OnValidSubmitAsync()
    {
        var user = await UserManager.FindByEmailAsync(Input!.Email);
        if (user is null)
        {
            _message = ConfirmationMessage;
            return;
        }

        var userId = await UserManager.GetUserIdAsync(user);
        var code = await UserManager.GenerateEmailConfirmationTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var callbackUrl =
            NavigationManager.GetUriWithQueryParameters(
                NavigationManager
                    .ToAbsoluteUri("Account/ConfirmEmail")
                    .AbsoluteUri,
                new Dictionary<string, object?>
                {
                    ["userId"] = userId,
                    ["code"] = code
                });

        await EmailSender.SendConfirmationLinkAsync(user, Input.Email, HtmlEncoder.Default.Encode(callbackUrl));
        _message = ConfirmationMessage;
    }

    private sealed class InputModel
    {
        [Required] 
        [EmailAddress] 
        public string Email { get; set; } = string.Empty;
    }
}