using Microsoft.AspNetCore.Components;

namespace Soteria2.Components.Layout;

public partial class NavMenu
{
    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    private string CurrentRelativeUrl =>
        NavigationManager.ToBaseRelativePath(NavigationManager.Uri);
}