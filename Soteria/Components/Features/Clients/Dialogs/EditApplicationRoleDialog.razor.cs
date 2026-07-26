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
    private IMudValidator<EditApplicationRoleRequest>
        EditApplicationRoleValidator { get; set; } = default!;

    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;

    [Parameter, EditorRequired]
    public EditApplicationRoleRequest Request { get; set; } = default!;

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
            await ClientService.UpdateApplicationRoleAsync(Request);
            MudDialog.Close(DialogResult.Ok(Request.Name));
        }
        catch (EditApplicationRoleValidationException exception)
        {
            ErrorMessages = exception.Failures
                .Select(failure => failure.ErrorMessage)
                .ToList();
        }
        catch (Exception)
        {
            ErrorMessages.Add(
                "The application role could not be updated. Review the entered values and try again.");
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