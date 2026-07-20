using Microsoft.AspNetCore.Components;
using MudBlazor;
using Soteria.Components.Features.Clients.Models;

// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Features.Clients.Dialogs;

public partial class CreateClientDialog
{
    [Inject]
    private ClientService ClientService { get; set; } = default!;
    [Inject]
    private ClientValidator ClientValidator { get; set; } = default!;

    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;
    
    private MudForm Form { get; set; } = default!;
    private CreateClientModel Model { get; } = new();
    private string? ErrorMessage { get; set; }
    private bool IsSaving { get; set; }

    private async Task SaveAsync()
    {
        ErrorMessage = null;
        
        await Form.ValidateAsync();

        if (!Form.IsValid)
        {
            return;
        }

        IsSaving = true;

        try
        {
            await ClientService.CreateClientAsync(
                new CreateClientRequest(
                    Model.ClientId,
                    Model.DisplayName,
                    Model.ClientSecret,
                    Model.ClientHost));

            MudDialog.Close(DialogResult.Ok(Model.ClientId.Trim()));
        }
        catch (ClientValidationException exception)
        {
            ErrorMessage = $"{exception.PropertyName} - {exception.Message}";
        }
        catch (Exception)
        {
            ErrorMessage = "The client application could not be created. Review the entered values and try again.";
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