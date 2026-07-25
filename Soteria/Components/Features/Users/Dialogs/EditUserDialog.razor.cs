using Microsoft.AspNetCore.Components;
using MudBlazor;

// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Features.Users.Dialogs;

public partial class EditUserDialog
{
    [Parameter]
    public EditUserRequest Request { get; set; } = default!;

    [Inject]
    private UserService UserService { get; set; } = default!;

    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;

    private List<string> ErrorMessages { get; set; } = [];
    private bool IsSaving { get; set; }

    private void Unlock()
    {
        Request.IsLockedOut = false;
        Request.LockoutEnd = null;
        Request.UnlockRequested = true;
    }

    private async Task SaveAsync()
    {
        ErrorMessages.Clear();
        IsSaving = true;

        try
        {
            await UserService.UpdateUserAsync(Request);
            MudDialog.Close(DialogResult.Ok(true));
        }
        catch (EditUserIdentityException exception)
        {
            ErrorMessages = exception.Errors
                .Select(error => error.Description)
                .ToList();
        }
        catch (Exception)
        {
            ErrorMessages.Add(
                "The user could not be updated. Review the account and try again.");
        }
        finally
        {
            IsSaving = false;
        }
    }

    private void Cancel()
    {
        MudDialog.Cancel();
    }

    private static string FormatLockoutEnd(DateTimeOffset? lockoutEnd)
    {
        return lockoutEnd?.ToLocalTime().ToString("g") ?? "Not locked out";
    }
}