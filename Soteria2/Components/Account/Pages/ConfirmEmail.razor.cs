using System.Text;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Soteria2.Data;

namespace Soteria2.Components.Account.Pages;

public partial class ConfirmEmail
{
    private string? _statusMessage;
    private bool _emailConfirmed;

    [Inject]
    private UserManager<ApplicationUser> UserManager { get; set; } = default!;

    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    [Inject]
    private IdentityRedirectManager RedirectManager { get; set; } = default!;

    [CascadingParameter]
    private HttpContext HttpContext { get; set; } = default!;

    [SupplyParameterFromQuery]
    private string? UserId { get; set; }

    [SupplyParameterFromQuery]
    private string? Code { get; set; }

    [SupplyParameterFromQuery]
    private string? ReturnUrl { get; set; }

    private string _loginUrl =>
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
            HttpContext.Response.StatusCode =
                StatusCodes.Status404NotFound;

            _statusMessage =
                $"Error loading user with ID '{UserId}'.";

            return;
        }

        string code;

        try
        {
            code = Encoding.UTF8.GetString(
                WebEncoders.Base64UrlDecode(Code));
        }
        catch (FormatException)
        {
            _statusMessage = "Error confirming your email.";
            return;
        }

        var result = await UserManager.ConfirmEmailAsync(
            user,
            code);

        _emailConfirmed = result.Succeeded;

        _statusMessage = result.Succeeded
            ? "Thank you for confirming your email."
            : "Error confirming your email.";
    }
}