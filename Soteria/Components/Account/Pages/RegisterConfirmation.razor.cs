using System.Text;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Soteria.Components.Account.Email;
using Soteria.Data;

namespace Soteria.Components.Account.Pages;

public partial class RegisterConfirmation
{
    private string? _emailConfirmationLink;
    private string? _statusMessage;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private IEmailSender<ApplicationUser> EmailSender { get; set; } = null!;
    [Inject] private NavigationManager NavigationManager { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = null!;
    [SupplyParameterFromQuery] private string? Email { get; set; }
    [SupplyParameterFromQuery] private string? ReturnUrl { get; set; }

    protected override async Task OnInitializedAsync()
    {
        if (Email is null)
        {
            RedirectManager.RedirectTo("");
            return;
        }

        var user = await UserManager.FindByEmailAsync(Email);
        if (user is null)
        {
            HttpContext.Response.StatusCode = StatusCodes.Status404NotFound;
            _statusMessage = "Error finding a user for the specified email.";
        }
        else if (EmailSender is not IdentityNoOpEmailSender)
        {
            var userId = await UserManager.GetUserIdAsync(user);
            var code = await UserManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            _emailConfirmationLink =
                NavigationManager.GetUriWithQueryParameters(
                    NavigationManager
                        .ToAbsoluteUri("Account/ConfirmEmail")
                        .AbsoluteUri,
                    new Dictionary<string, object?>
                    {
                        ["userId"] = userId,
                        ["code"] = code,
                        ["returnUrl"] = ReturnUrl
                    });
        }
    }
}