using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Soteria.Data;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.Authorization;

public sealed class AdministrationAuthorizationHandler(SoteriaDbContext dbContext) : AuthorizationHandler<AdministrationRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AdministrationRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            return;
        }

        var userIdValue = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(userIdValue, out var userId))
        {
            return;
        }

        var isSoteriaAdministrator = await dbContext.UserSystemRoles
                .AsNoTracking()
                .AnyAsync(assignment => assignment.UserId == userId && assignment.SystemRoleId == SystemRoleIds.SoteriaAdministrator);

        if (isSoteriaAdministrator)
        {
            context.Succeed(requirement);
            return;
        }

        var isClientAdministrator = await dbContext.ClientMemberships
                .AsNoTracking()
                .AnyAsync(membership => membership.UserId == userId && membership.MembershipLevel == MembershipLevel.Administrator);

        if (isClientAdministrator)
        {
            context.Succeed(requirement);
        }
    }
}