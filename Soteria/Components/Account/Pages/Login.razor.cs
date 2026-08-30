using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;
// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Account.Pages;

public partial class Login
{
    private string? _errorMessage;
    private EditContext _editContext = null!;

    [Inject] private SignInManager<ApplicationUser> SignInManager { get; set; } = null!;
    [Inject] private ILogger<Login> Logger { get; set; } = null!;
    [Inject] private NavigationManager NavigationManager { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = null!;
    [SupplyParameterFromForm] private InputModel Input { get; set; } = null!;
    [SupplyParameterFromQuery] private string? ReturnUrl { get; set; }

    private string RegisterUrl =>
        NavigationManager.GetUriWithQueryParameters(
            "Account/Register",
            new Dictionary<string, object?>
            {
                ["ReturnUrl"] = ReturnUrl
            });

    protected override async Task OnInitializedAsync()
    {
        // this is needed, even though non-nullable
        Input ??= new InputModel();

        _editContext = new EditContext(Input);

        if (HttpMethods.IsGet(HttpContext.Request.Method))
        {
            // Clear the existing external cookie to ensure a clean login process.
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        }
    }

    private async Task LoginUserAsync()
    {
        if (!string.IsNullOrEmpty(Input.Passkey?.Error))
        {
            _errorMessage = $"Error: {Input.Passkey.Error}";
            return;
        }

        SignInResult result;
        if (!string.IsNullOrEmpty(Input.Passkey?.CredentialJson))
        {
            // Passkey sign-in doesn't use the password form fields.
            result = await SignInManager.PasskeySignInAsync(Input.Passkey.CredentialJson);
        }
        else
        {
            if (!_editContext.Validate())
            {
                return;
            }

            result = await SignInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false);
        }

        if (result.Succeeded)
        {
            Logger.LogInformation("User logged in.");

            var user = await SignInManager.UserManager.FindByEmailAsync(Input.Email);
            if (user?.RequiresPasswordChange == true)
            {
                RedirectManager.RedirectTo(
                    "Account/Manage/ChangePassword",
                    new Dictionary<string, object?>
                    {
                        ["ReturnUrl"] = ReturnUrl
                    });

                return;
            }

            RedirectManager.RedirectTo(ReturnUrl);
        }
        else if (result.RequiresTwoFactor)
        {
            RedirectManager.RedirectTo(
                "Account/LoginWith2fa",
                new Dictionary<string, object?>
                {
                    ["returnUrl"] = ReturnUrl,
                    ["rememberMe"] = Input.RememberMe
                });
        }
        else if (result.IsLockedOut)
        {
            Logger.LogWarning("User account locked out.");
            RedirectManager.RedirectTo("Account/Lockout");
        }
        else
        {
            _errorMessage = "Error: Invalid login attempt.";
        }
    }

    private sealed class InputModel
    {
        [Required] 
        [EmailAddress] 
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Remember me?")] 
        public bool RememberMe { get; set; }

        public PasskeyInputModel? Passkey { get; set; }
    }
}