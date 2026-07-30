using Microsoft.AspNetCore.Components;
using MudBlazor;

namespace Soteria.Components.Features.Clients.Dialogs;

public partial class DeleteApplicationRoleDialog
{
    [Inject]
    private ClientService ClientService { get; set; } = default!;

    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;
    [Parameter, EditorRequired]
    public DeleteApplicationRoleRequest Request { get; set; } = default!;

    private List<string> ErrorMessages { get; set; } = [];
    private bool IsDeleting { get; set; }

    private async Task DeleteAsync()
    {
        ErrorMessages.Clear();
        IsDeleting = true;

        try
        {
            await ClientService.RemoveApplicationRoleAsync(Request.ClientId, Request.Name);
            MudDialog.Close(DialogResult.Ok(Request.Name));
        }
        catch (ApplicationRoleNotFoundException)
        {
            ErrorMessages.Add("The Application Role no longer exists or does not belong to this client application.");
        }
        catch (Exception)
        {
            ErrorMessages.Add("The Application Role could not be deleted. Try again.");
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
}