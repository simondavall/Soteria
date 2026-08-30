using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;
// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Account.Pages.Manage;

public partial class ChangePassword
{
    private string? _message;
    private ApplicationUser? _user;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private SignInManager<ApplicationUser> SignInManager { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;
    [Inject] private ILogger<ChangePassword> Logger { get; set; } = null!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = null!;
    [SupplyParameterFromForm] private InputModel Input { get; set; } = null!;
    [SupplyParameterFromQuery] private string? ReturnUrl { get; set; }

    protected override async Task OnInitializedAsync()
    {
        // this is needed, even though non-nullable
        Input ??= new InputModel();

        _user = await UserManager.GetUserAsync(HttpContext.User);
        if (_user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        var hasPassword = await UserManager.HasPasswordAsync(_user);
        if (!hasPassword)
        {
            RedirectManager.RedirectTo("Account/Manage/SetPassword");
        }
    }

    private async Task OnValidSubmitAsync()
    {
        if (_user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        if (await UserManager.CheckPasswordAsync(_user, Input.NewPassword))
        {
            _message = "Error: Your new password must be different from your current password.";
            return;
        }
        
        var passwordChangeRequired = _user.RequiresPasswordChange;

        var result = await UserManager.ChangePasswordAsync(_user, Input.OldPassword, Input.NewPassword);
        if (!result.Succeeded)
        {
            _message = $"Error: {string.Join(", ", result.Errors.Select(error => error.Description))}";
            return;
        }

        if (passwordChangeRequired)
        {
            _user.RequiresPasswordChange = false;

            var updateResult = await UserManager.UpdateAsync(_user);
            if (!updateResult.Succeeded)
            {
                _user.RequiresPasswordChange = true;
                _message = $"Error: {string.Join(", ", updateResult.Errors.Select(error => error.Description))}";
                return;
            }
        }

        await SignInManager.RefreshSignInAsync(_user);
        Logger.LogInformation("User changed their password successfully.");

        if (passwordChangeRequired)
        {
            RedirectManager.RedirectTo(ReturnUrl);
            return;
        }

        RedirectManager.RedirectToCurrentPageWithStatus("Your password has been changed.", HttpContext);
    }

    private sealed class InputModel
    {
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Current password")]
        public string OldPassword { get; set; } = string.Empty;

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        public string NewPassword { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm new password")]
        [Compare(nameof(NewPassword), ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}