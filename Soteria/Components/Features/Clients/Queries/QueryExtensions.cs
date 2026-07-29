using Soteria.Components.Features.Authorization;
using Soteria.Data;
using Soteria.Data.Authorization;
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

    public static IQueryable<TSource> WhereUserAdministered<TSource>(this IQueryable<TSource> query, CurrentUserAdministrationScope scope)
        where TSource : ApplicationUser
    {
        IEnumerable<Guid> administeredClientIds = scope.AdministeredClientIds.ToArray();
        return query.Where(user => user.ClientMemberships.Any(membership => administeredClientIds.Contains(membership.ApplicationId)));
    }
    
    public static IQueryable<TSource> WhereClientMembershipAdministered<TSource>(this IQueryable<TSource> query, CurrentUserAdministrationScope scope)
        where TSource : ClientMembership
    {
        IEnumerable<Guid> administeredClientIds = scope.AdministeredClientIds.ToArray();
        return query.Where(membership => administeredClientIds.Contains(membership.ApplicationId));
    }
}