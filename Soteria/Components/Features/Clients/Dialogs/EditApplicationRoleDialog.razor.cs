
using Microsoft.AspNetCore.Components;
using MudBlazor;
using Soteria.Components.Features.Shared;

// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Features.Clients.Dialogs;

public partial class EditApplicationRoleDialog
{
    [Inject]
    private ClientService ClientService { get; set; } = default!;
    [Inject]
    private IMudValidator<EditApplicationRoleRequest> EditApplicationRoleValidator { get; set; } = default!;
    [Inject]
    private IDialogService DialogService { get; set; } = default!;
    
    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;
    [Parameter, EditorRequired]
    public EditApplicationRoleRequest Request { get; set; } = default!;

    private MudForm Form { get; set; } = default!;
    private List<string> ErrorMessages { get; set; } = [];
    private bool IsSaving { get; set; }
    private bool IsDeleting { get; set; }

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
            await ClientService.UpdateApplicationRoleAsync(Request);
            //MudDialog.Close(DialogResult.Ok(Request.Name));
            MudDialog.Close(DialogResult.Ok(new EditApplicationRoleDialogResult(false)));
        }
        catch (EditApplicationRoleValidationException exception)
        {
            ErrorMessages = exception.Failures
                .Select(failure => failure.ErrorMessage)
                .ToList();
        }
        catch (Exception)
        {
            ErrorMessages.Add("The application role could not be updated. Review the entered values and try again.");
        }
        finally
        {
            IsSaving = false;
        }
    }

    private async Task ConfirmDeleteAsync()
    {
        ErrorMessages.Clear();
        IsDeleting = true;

        try
        {
            var removalRequest = await ClientService.GetApplicationRoleForRemovalAsync(Request.ClientId, Request.Name);
            if (removalRequest is null)
            {
                ErrorMessages.Add("The Application Role no longer exists or does not belong to this client application.");
                return;
            }

            var parameters = new DialogParameters
            {
                [nameof(DeleteApplicationRoleDialog.Request)] = removalRequest
            };

            var options = new DialogOptions
            {
                MaxWidth = MaxWidth.Small,
                FullWidth = true,
                CloseButton = true,
                CloseOnEscapeKey = true
            };

            var dialog = await DialogService.ShowAsync<DeleteApplicationRoleDialog>("Delete Application Role", parameters, options);
            var result = await dialog.Result;
            if (result is null || result.Canceled)
            {
                return;
            }

            MudDialog.Close(DialogResult.Ok(new EditApplicationRoleDialogResult(true)));
        }
        catch (Exception)
        {
            ErrorMessages.Add("The Application Role could not be prepared for deletion. Try again.");
        }
        finally
        {
            IsDeleting = false;
        }
    }
    private void Cancel()
    {
        MudDialog.Cancel();
    }
    
    public sealed record EditApplicationRoleDialogResult(bool WasDeleted);
}