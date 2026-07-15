using System.Text;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Soteria.Data;

namespace Soteria.Components.Account.Pages;

public partial class ConfirmEmail
{
    private string? _statusMessage;
    private bool _emailConfirmed;
    private bool _isAuthenticated;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private NavigationManager NavigationManager { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = null!;
    [SupplyParameterFromQuery] private string? UserId { get; set; }
    [SupplyParameterFromQuery] private string? Code { get; set; }
    [SupplyParameterFromQuery] private string? ReturnUrl { get; set; }

    private string LoginUrl =>
        NavigationManager.GetUriWithQueryParameters(
            "Account/Login",
            new Dictionary<string, object?>
            {
                ["ReturnUrl"] = ReturnUrl
            });

    protected override async Task OnInitializedAsync()
    {
        if (UserId is null || Code is null)
        {
            RedirectManager.RedirectTo("");
            return;
        }

        var user = await UserManager.FindByIdAsync(UserId);
        if (user is null)
        {
            HttpContext.Response.StatusCode = StatusCodes.Status404NotFound;
            _statusMessage = $"Error loading user with ID '{UserId}'.";
            return;
        }

        string code;
        try
        {
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(Code));
        }
        catch (FormatException)
        {
            _statusMessage = "Error confirming your email.";
            return;
        }

        var result = await UserManager.ConfirmEmailAsync(user, code);
        _emailConfirmed = result.Succeeded;
        _isAuthenticated = HttpContext.User.Identity?.IsAuthenticated ?? false;
        _statusMessage = result.Succeeded ? "Thank you for confirming your email." : "Error confirming your email.";
    }
}