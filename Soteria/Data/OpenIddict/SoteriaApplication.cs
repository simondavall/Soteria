using OpenIddict.EntityFrameworkCore.Models;
using Soteria.Data.Authorization;

namespace Soteria.Data.OpenIddict;

public class SoteriaApplication
    : OpenIddictEntityFrameworkCoreApplication<Guid, SoteriaAuthorization, SoteriaToken>
{
    public bool IsEnabled { get; set; } = true;

    public ICollection<ClientMembership> ClientMemberships { get; set; } = [];

    public ICollection<ApplicationRole> ApplicationRoles { get; set; } = [];
}