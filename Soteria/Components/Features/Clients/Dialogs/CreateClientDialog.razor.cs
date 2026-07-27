using Microsoft.AspNetCore.Components;
using MudBlazor;
using Soteria.Components.Features.Shared;

// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Features.Clients.Dialogs;

public partial class CreateClientDialog
{
    [Inject]
    private ClientService ClientService { get; set; } = default!;
    [Inject]
    private IMudValidator<CreateClientRequest> CreateClientValidator { get; set; } = default!;

    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;
    
    private MudForm Form { get; set; } = default!;
    private CreateClientRequest Request { get; } = new();
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
            await ClientService.CreateClientAsync(Request);
            MudDialog.Close(DialogResult.Ok(Request.ClientId.Trim()));
        }
        catch (CreateClientValidationException exception)
        {
            ErrorMessages = exception.Failures.Select(e => e.ErrorMessage).ToList();
        }
        catch (UnauthorizedAccessException exception)
        {
            ErrorMessages.Add(exception.Message);
        }
        catch (Exception)
        {
            ErrorMessages.Add("The client application could not be created. Review the entered values and try again.");
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