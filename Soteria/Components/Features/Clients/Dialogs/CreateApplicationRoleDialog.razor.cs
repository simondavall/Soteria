using Microsoft.AspNetCore.Components;
using MudBlazor;
using Soteria.Components.Features.Shared;

// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Features.Clients.Dialogs;

public partial class CreateApplicationRoleDialog
{
    [Inject]
    private ClientService ClientService { get; set; } = default!;
    [Inject]
    private IMudValidator<CreateApplicationRoleRequest> CreateApplicationRoleValidator { get; set; } = default!;

    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;
    [Parameter]
    public string ClientId { get; set; } = string.Empty;

    private MudForm Form { get; set; } = default!;
    private CreateApplicationRoleRequest Request { get; } = new();
    private List<string> ErrorMessages { get; set; } = [];
    private bool IsSaving { get; set; }

    protected override void OnParametersSet()
    {
        Request.ClientId = ClientId;
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
            await ClientService.CreateApplicationRoleAsync(Request);
            MudDialog.Close(DialogResult.Ok(Request.Name));
        }
        catch (CreateApplicationRoleValidationException exception)
        {
            ErrorMessages = exception.Failures
                .Select(failure => failure.ErrorMessage)
                .ToList();
        }
        catch (Exception)
        {
            ErrorMessages.Add("The application role could not be created. Review the entered values and try again.");
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