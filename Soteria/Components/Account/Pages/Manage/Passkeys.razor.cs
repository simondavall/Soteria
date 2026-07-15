using System.Buffers.Text;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;

namespace Soteria.Components.Account.Pages.Manage;

public partial class Passkeys
{
    private const int MaxPasskeyCount = 100;

    private ApplicationUser? _user;
    private IList<UserPasskeyInfo>? _currentPasskeys;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private SignInManager<ApplicationUser> SignInManager { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = null!;
    [SupplyParameterFromForm] private string? Action { get; set; }
    [SupplyParameterFromForm] private string? CredentialId { get; set; }
    [SupplyParameterFromForm(FormName = "add-passkey")] private PasskeyInputModel? Input { get; set; }

    protected override async Task OnInitializedAsync()
    {
        _user = await UserManager.GetUserAsync(HttpContext.User);

        if (_user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        _currentPasskeys = await UserManager.GetPasskeysAsync(_user);
    }

    private async Task AddPasskeyAsync()
    {
        if (_user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        if (!string.IsNullOrEmpty(Input!.Error))
        {
            RedirectManager.RedirectToCurrentPageWithStatus($"Error: {Input.Error}", HttpContext);
            return;
        }

        if (string.IsNullOrEmpty(Input.CredentialJson))
        {
            RedirectManager.RedirectToCurrentPageWithStatus("Error: The browser did not provide a passkey.", HttpContext);
            return;
        }

        if (_currentPasskeys!.Count >= MaxPasskeyCount)
        {
            RedirectManager.RedirectToCurrentPageWithStatus("Error: You have reached the maximum number of allowed passkeys.", 
                HttpContext);
            return;
        }

        var attestationResult = await SignInManager.PerformPasskeyAttestationAsync(Input.CredentialJson);

        if (!attestationResult.Succeeded)
        {
            RedirectManager.RedirectToCurrentPageWithStatus($"Error: Could not add the passkey: {attestationResult.Failure.Message}", HttpContext);
            return;
        }

        var addPasskeyResult = await UserManager.AddOrUpdatePasskeyAsync(_user, attestationResult.Passkey);
        if (!addPasskeyResult.Succeeded)
        {
            RedirectManager.RedirectToCurrentPageWithStatus("Error: The passkey could not be added to your account.", HttpContext);
            return;
        }

        var credentialId = Base64Url.EncodeToString(attestationResult.Passkey.CredentialId);
        RedirectManager.RedirectTo($"Account/Manage/RenamePasskey/{credentialId}");
    }

    private async Task UpdatePasskeyAsync()
    {
        switch (Action)
        {
            case "rename":
                RedirectManager.RedirectTo($"Account/Manage/RenamePasskey/{CredentialId}");
                break;

            case "delete":
                await DeletePasskeyAsync();
                break;

            default:
                RedirectManager.RedirectToCurrentPageWithStatus($"Error: Unknown action '{Action}'.", HttpContext);
                break;
        }
    }

    private async Task DeletePasskeyAsync()
    {
        if (_user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        byte[] credentialId;

        try
        {
            credentialId = Base64Url.DecodeFromChars(CredentialId);
        }
        catch (FormatException)
        {
            RedirectManager.RedirectToCurrentPageWithStatus("Error: The specified passkey ID had an invalid format.",
                HttpContext);
            return;
        }

        var result = await UserManager.RemovePasskeyAsync(_user, credentialId);
        if (!result.Succeeded)
        {
            RedirectManager.RedirectToCurrentPageWithStatus("Error: The passkey could not be deleted.", HttpContext);
            return;
        }

        RedirectManager.RedirectToCurrentPageWithStatus("Passkey deleted successfully.", HttpContext);
    }
}