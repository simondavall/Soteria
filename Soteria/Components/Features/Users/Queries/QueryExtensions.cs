using Soteria.Components.Features.Authorization;
using Soteria.Data;

namespace Soteria.Components.Features.Users.Queries;

public static class QueryExtensions
{
    public static IQueryable<TSource> WhereUserAdministered<TSource>(this IQueryable<TSource> query, CurrentUserAdministrationScope scope)
        where TSource : ApplicationUser
    {
        IEnumerable<Guid> administeredClientIds = scope.AdministeredClientIds.ToArray();
        return query.Where(user => user.ClientMemberships.Any(membership => administeredClientIds.Contains(membership.ApplicationId)));
    }
}