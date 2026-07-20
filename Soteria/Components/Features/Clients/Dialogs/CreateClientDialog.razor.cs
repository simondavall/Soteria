using Microsoft.AspNetCore.Components;
using MudBlazor;

namespace Soteria.Components.Features.Clients.Dialogs;

public partial class CreateClientDialog
{
    [Inject]
    private ClientService ClientService { get; set; } = default!;
    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;
    
    private MudForm Form { get; set; } = default!;
    private CreateClientModel Model { get; } = new();
    private Dictionary<string, string> FieldErrors { get; } = [];
    private string? ErrorMessage { get; set; }
    private bool IsSaving { get; set; }

    private async Task SaveAsync()
    {
        FieldErrors.Clear();
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
            FieldErrors[exception.PropertyName] = exception.Message;
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

    private bool HasError(string propertyName)
    {
        return FieldErrors.ContainsKey(propertyName);
    }

    private string? GetError(string propertyName)
    {
        return FieldErrors.GetValueOrDefault(propertyName);
    }

    private sealed class CreateClientModel
    {
        public string ClientId { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public string ClientHost { get; set; } = string.Empty;
    }
}