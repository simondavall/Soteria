using System.Text;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Soteria.Data;

namespace Soteria.Components.Account.Pages;

public partial class ConfirmEmailChange
{
    private string? _message;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = default!;
    [Inject] private SignInManager<ApplicationUser> SignInManager { get; set; } = default!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = default!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = default!;
    [SupplyParameterFromQuery] private string? UserId { get; set; }
    [SupplyParameterFromQuery] private string? Email { get; set; }
    [SupplyParameterFromQuery] private string? Code { get; set; }

    protected override async Task OnInitializedAsync()
    {
        if (UserId is null || Email is null || Code is null)
        {
            RedirectManager.RedirectToWithStatus(
                "Account/Login",
                "Error: Invalid email change confirmation link.",
                HttpContext);

            return;
        }

        var user = await UserManager.FindByIdAsync(UserId);
        if (user is null)
        {
            _message = $"Unable to find user with ID '{UserId}'.";
            return;
        }

        string code;
        try
        {
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(Code));
        }
        catch (FormatException)
        {
            _message = "Error changing email.";
            return;
        }

        var result = await UserManager.ChangeEmailAsync(user, Email, code);
        if (!result.Succeeded)
        {
            _message = "Error changing email.";
            return;
        }

        // In our UI email and username are one and the same, so when we update the email
        // we need to update the username.
        var setUserNameResult = await UserManager.SetUserNameAsync(user, Email);
        if (!setUserNameResult.Succeeded)
        {
            _message = "Error changing user name.";
            return;
        }

        await SignInManager.RefreshSignInAsync(user);
        _message = "Thank you for confirming your email change.";
    }
}