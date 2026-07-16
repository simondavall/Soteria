using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;
// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Account.Pages.Manage;

public partial class DeletePersonalData
{
    private string? _message;
    private ApplicationUser? _user;
    private bool _requirePassword;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private SignInManager<ApplicationUser> SignInManager { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;
    [Inject] private ILogger<DeletePersonalData> Logger { get; set; } = null!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = null!;
    [SupplyParameterFromForm] private InputModel Input { get; set; } = null!;

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

        _requirePassword = await UserManager.HasPasswordAsync(_user);
    }

    private async Task OnValidSubmitAsync()
    {
        if (_user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        if (_requirePassword && !await UserManager.CheckPasswordAsync(_user, Input.Password))
        {
            _message = "Error: Incorrect password.";
            return;
        }
        
        var result = await UserManager.DeleteAsync(_user);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException("Unexpected error occurred deleting user.");
        }

        await SignInManager.SignOutAsync();

        var userId = await UserManager.GetUserIdAsync(_user);
        Logger.LogInformation("User with ID '{UserId}' deleted themselves.", userId);

        RedirectManager.RedirectToCurrentPage();
    }

    private sealed class InputModel
    {
        [DataType(DataType.Password)] 
        public string Password { get; set; } = string.Empty;
    }
}