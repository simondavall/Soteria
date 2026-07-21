using OpenIddict.EntityFrameworkCore.Models;

namespace Soteria.Data.OpenIddict;

public sealed class SoteriaToken : OpenIddictEntityFrameworkCoreToken<Guid, SoteriaApplication, SoteriaAuthorization>;