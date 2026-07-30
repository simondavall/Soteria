using Microsoft.AspNetCore.Components;
using MudBlazor;
using Soteria.Components.Features.Authorization;
using Soteria.Components.Features.Shared;

// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Features.Users.Dialogs;

public partial class EditUserDialog
{
    [Inject]
    private UserService UserService { get; set; } = default!;
    [Inject]
    private ICurrentUserContext CurrentUserContext { get; set; } = default!;
    [Inject]
    private IMudValidator<EditUserRequest> EditUserValidator { get; set; } = default!;
    
    [Parameter]
    public EditUserRequest Request { get; set; } = default!;
    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;

    private List<string> ErrorMessages { get; set; } = [];
    private bool IsSaving { get; set; }
    private MudForm Form { get; set; } = default!;
    private bool CanManageSoteriaAdministrators { get; set; }

    protected override async Task OnInitializedAsync()
    {
        CanManageSoteriaAdministrators = await CurrentUserContext.IsSoteriaAdministratorAsync();
    }
    
    private void Unlock()
    {
        Request.IsLockedOut = false;
        Request.LockoutEnd = null;
        Request.UnlockRequested = true;
    }

    private async Task SaveAsync()
    {
        ErrorMessages.Clear();

        await Form.ValidateAsync();

        if (!Form.IsValid)
        {
            return;
        }

        IsSaving = true;

        try
        {
            await UserService.UpdateUserAsync(Request);
            MudDialog.Close(DialogResult.Ok(true));
        }
        catch (EditUserValidationException exception)
        {
            ErrorMessages = exception.Failures.Select(error => error.ErrorMessage).Distinct().ToList();
        }
        catch (EditUserIdentityException exception)
        {
            ErrorMessages = exception.Errors.Select(error => error.Description).ToList();
        }
        catch (UnauthorizedAccessException exception)
        {
            ErrorMessages.Add(exception.Message);
        }
        catch (Exception)
        {
            ErrorMessages.Add("The user could not be updated. Review the account and try again.");
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