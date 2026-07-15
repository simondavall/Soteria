using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;

namespace Soteria.Components.Account.Pages.Manage;

public partial class DeletePersonalData
{
    private string? _message;
    private ApplicationUser? _user;
    private bool _requirePassword;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = default!;
    [Inject] private SignInManager<ApplicationUser> SignInManager { get; set; } = default!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = default!;
    [Inject] private ILogger<DeletePersonalData> Logger { get; set; } = default!;

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

        var userId = await UserManager.GetUserIdAsync(_user);
        var result = await UserManager.DeleteAsync(_user);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException("Unexpected error occurred deleting user.");
        }

        await SignInManager.SignOutAsync();

        Logger.LogInformation("User with ID '{UserId}' deleted themselves.", userId);

        RedirectManager.RedirectToCurrentPage();
    }

    private sealed class InputModel
    {
        [DataType(DataType.Password)] 
        public string Password { get; set; } = string.Empty;
    }
}