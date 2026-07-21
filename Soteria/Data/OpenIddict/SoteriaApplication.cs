using OpenIddict.EntityFrameworkCore.Models;

namespace Soteria.Data.OpenIddict;

public sealed class SoteriaApplication : OpenIddictEntityFrameworkCoreApplication<Guid, SoteriaAuthorization, SoteriaToken>
{
    public bool IsEnabled { get; set; } = true;
}