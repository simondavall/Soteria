using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;

namespace Soteria.Components.Account.Pages.Manage;

public partial class ChangePassword
{
    private string? _message;
    private ApplicationUser? _user;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = default!;
    [Inject] private SignInManager<ApplicationUser> SignInManager { get; set; } = default!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = default!;
    [Inject] private ILogger<ChangePassword> Logger { get; set; } = default!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = default!;
    [SupplyParameterFromForm] private InputModel Input { get; set; } = new();

    protected override async Task OnInitializedAsync()
    {
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

        var result = await UserManager.ChangePasswordAsync(_user, Input.OldPassword, Input.NewPassword);
        if (!result.Succeeded)
        {
            _message = $"Error: {string.Join(", ", result.Errors.Select(error => error.Description))}";
            return;
        }

        await SignInManager.RefreshSignInAsync(_user);

        Logger.LogInformation("User changed their password successfully.");

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