using Soteria.Components.Features.Authorization;
using Soteria.Data.OpenIddict;

namespace Soteria.Components.Features.Clients.Queries;

public static class QueryExtensions
{
    public static IQueryable<TSource> WhereClientsAdministered<TSource>(this IQueryable<TSource> query, CurrentUserAdministrationScope scope)
    where TSource : SoteriaApplication
    {
        IEnumerable<Guid> administeredClientIds = scope.AdministeredClientIds.ToArray();
        return query.Where(application => administeredClientIds.Contains(application.Id));
    }
}