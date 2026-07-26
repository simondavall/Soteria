using Microsoft.AspNetCore.Components;
using MudBlazor;

namespace Soteria.Components.Features.Users.Dialogs;

public partial class DeleteClientMembershipDialog
{
    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;
    [Parameter]
    public string ApplicationName { get; set; } = string.Empty;

    private void Cancel()
    {
        MudDialog.Cancel();
    }

    private void Confirm()
    {
        MudDialog.Close(DialogResult.Ok(true));
    }
}