using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Soteria.Data;
using Soteria.Data.Authorization;
using Soteria.Data.OpenIddict;

namespace Soteria.Components.Features.OpenIdConnect;

public interface IOpenIdClientMembershipResolver
{
    Task<OpenIdAuthorizationResolution> ResolveAsync(string? clientId, string? subject, CancellationToken cancellationToken = default);
}

public sealed class OpenIdClientMembershipResolver(IOpenIddictApplicationManager applicationManager, SoteriaDbContext dbContext)
    : IOpenIdClientMembershipResolver
{
    public async Task<OpenIdAuthorizationResolution> ResolveAsync(string? clientId, string? subject, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(clientId))
        {
            return OpenIdAuthorizationResolution.Failed(OpenIdAuthorizationResolutionFailure.ClientIdentifierUnavailable);
        }

        var application = await applicationManager.FindByClientIdAsync(clientId, cancellationToken);
        if (application is not SoteriaApplication soteriaApplication)
        {
            return OpenIdAuthorizationResolution.Failed(OpenIdAuthorizationResolutionFailure.ClientApplicationNotFound);
        }

        var applicationIdValue = await applicationManager.GetIdAsync(application, cancellationToken);
        if (!Guid.TryParse(applicationIdValue, out var applicationId))
        {
            return OpenIdAuthorizationResolution.Failed(OpenIdAuthorizationResolutionFailure.ClientApplicationIdentifierInvalid);
        }

        if (!Guid.TryParse(subject, out var userId))
        {
            return OpenIdAuthorizationResolution.Failed(OpenIdAuthorizationResolutionFailure.IdentityUserNotFound);
        }

        var user = await dbContext.Users
                .AsNoTracking()
                .SingleOrDefaultAsync(candidate => candidate.Id == userId, cancellationToken);

        if (user is null)
        {
            return OpenIdAuthorizationResolution.Failed(OpenIdAuthorizationResolutionFailure.IdentityUserNotFound);
        }

        var clientMembership =
            await dbContext.ClientMemberships
                .AsNoTracking()
                .Include(membership => membership.ApplicationRoleAssignments)
                .ThenInclude(assignment => assignment.ApplicationRole)
                .SingleOrDefaultAsync(membership => membership.UserId == user.Id &&
                                                    membership.ApplicationId == applicationId, 
                    cancellationToken);

        if (clientMembership is null)
        {
            var unresolvedContext =
                new ResolvedOpenIdAuthorizationContext(
                    soteriaApplication,
                    user,
                    ClientMembership: null,
                    ApplicationRoleNames: []);

            return OpenIdAuthorizationResolution.Failed(OpenIdAuthorizationResolutionFailure.ClientMembershipNotFound, unresolvedContext);
        }

        var applicationRoleNames =
            clientMembership.ApplicationRoleAssignments
                .Where(assignment => assignment.ApplicationId == applicationId &&
                                     assignment.ApplicationRole.ApplicationId == applicationId)
                .Select(assignment => assignment.ApplicationRole.Name)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(roleName => roleName, StringComparer.Ordinal)
                .ToList();

        return OpenIdAuthorizationResolution.Success(
            new ResolvedOpenIdAuthorizationContext(
                soteriaApplication,
                user,
                clientMembership,
                applicationRoleNames));
    }
}