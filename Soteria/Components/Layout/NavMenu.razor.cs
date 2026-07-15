using Microsoft.AspNetCore.Components;

namespace Soteria.Components.Layout;

public partial class NavMenu
{
    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    private string CurrentRelativeUrl =>
        NavigationManager.ToBaseRelativePath(NavigationManager.Uri);
}