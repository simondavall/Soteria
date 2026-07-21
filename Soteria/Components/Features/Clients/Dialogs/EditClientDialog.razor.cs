using Microsoft.AspNetCore.Components;
using MudBlazor;
using Soteria.Components.Features.Shared;

// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Features.Clients.Dialogs;

public partial class EditClientDialog
{
    [Parameter]
    public EditClientRequest Request { get; set; } = default!;

    [Inject]
    private ClientService ClientService { get; set; } = default!;

    [Inject]
    private IMudValidator<EditClientRequest> EditClientValidator
    {
        get;
        set;
    } = default!;

    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;

    private MudForm Form { get; set; } = default!;
    private List<string> ErrorMessages { get; set; } = [];
    private bool IsSaving { get; set; }

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
            await ClientService.UpdateClientAsync(Request);
            MudDialog.Close(DialogResult.Ok(true));
        }
        catch (EditClientValidationException exception)
        {
            ErrorMessages =
                exception.Failures
                    .Select(error => error.ErrorMessage)
                    .ToList();
        }
        catch (Exception)
        {
            ErrorMessages.Add(
                "The client application could not be updated. " +
                "Review the entered values and try again.");
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
}