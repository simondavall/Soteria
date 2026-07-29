using Soteria.Components.Features.Authorization;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.ClientMemberships.Queries;

public static class QueryExtensions
{
    public static IQueryable<TSource> WhereClientMembershipAdministered<TSource>(this IQueryable<TSource> query, 
        CurrentUserAdministrationScope scope) where TSource : ClientMembership
    {
        IEnumerable<Guid> administeredClientIds = scope.AdministeredClientIds.ToArray();

        return query.Where(membership => administeredClientIds.Contains(membership.ApplicationId));
    }
}