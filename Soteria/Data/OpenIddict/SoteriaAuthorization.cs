using OpenIddict.EntityFrameworkCore.Models;

namespace Soteria.Data.OpenIddict;

public sealed class SoteriaAuthorization : OpenIddictEntityFrameworkCoreAuthorization<Guid, SoteriaApplication, SoteriaToken>;