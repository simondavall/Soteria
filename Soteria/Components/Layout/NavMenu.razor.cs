using Microsoft.AspNetCore.Components;
using Soteria.Data.Authorization;

namespace Soteria.Components.Layout;

public partial class NavMenu
{
    [Inject]
    private NavigationManager NavigationManager { get; set; } = null!;
    [Inject]
    private SoteriaAdministratorInitializer SoteriaAdministratorInitializer { get; set; } = null!;

    private bool BootstrapRegistrationRequired => SoteriaAdministratorInitializer.BootstrapRegistrationRequired;

    private string CurrentRelativeUrl => NavigationManager.ToBaseRelativePath(NavigationManager.Uri);
}