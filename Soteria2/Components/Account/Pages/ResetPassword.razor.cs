using System.ComponentModel.DataAnnotations;
using System.Text;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Soteria2.Data;

namespace Soteria2.Components.Account.Pages;

public partial class ResetPassword
{
    private IEnumerable<IdentityError>? _identityErrors;

    [Inject]
    private IdentityRedirectManager RedirectManager { get; set; } = default!;

    [Inject]
    private UserManager<ApplicationUser> UserManager { get; set; } = default!;

    [SupplyParameterFromForm]
    private InputModel Input { get; set; } = default!;

    [SupplyParameterFromQuery]
    private string? Code { get; set; }

    private string? Message =>
        _identityErrors is null
            ? null
            : $"Error: {string.Join(
                ", ",
                _identityErrors.Select(error => error.Description))}";

    protected override void OnInitialized()
    {
        Input ??= new InputModel();

        if (Code is null)
        {
            RedirectManager.RedirectTo(
                "Account/InvalidPasswordReset");

            return;
        }

        Input.Code = Encoding.UTF8.GetString(
            WebEncoders.Base64UrlDecode(Code));
    }

    private async Task OnValidSubmitAsync()
    {
        var user = await UserManager.FindByEmailAsync(Input.Email);

        if (user is null)
        {
            // Don't reveal that the user does not exist.
            RedirectManager.RedirectTo(
                "Account/ResetPasswordConfirmation");

            return;
        }

        var result = await UserManager.ResetPasswordAsync(
            user,
            Input.Code,
            Input.Password);

        if (result.Succeeded)
        {
            RedirectManager.RedirectTo(
                "Account/ResetPasswordConfirmation");

            return;
        }

        _identityErrors = result.Errors;
    }

    private sealed class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(
            100,
            ErrorMessage =
                "The {0} must be at least {2} and at max {1} characters long.",
            MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare(
            nameof(Password),
            ErrorMessage =
                "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required]
        public string Code { get; set; } = string.Empty;
    }
}