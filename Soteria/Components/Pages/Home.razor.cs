using Microsoft.AspNetCore.Components;
using MudBlazor;

namespace Soteria.Components.Pages;

public partial class Home
{
    [Inject]
    private ISnackbar Snackbar { get; set; } = default!;

    private void VerifyMudBlazor()
    {
        Snackbar.Add(
            "MudBlazor is configured successfully.",
            Severity.Success);
    }
}