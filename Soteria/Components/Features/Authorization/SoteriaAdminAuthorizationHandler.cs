using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Soteria.Data;
using Soteria.Data.Authorization;

namespace Soteria.Components.Features.Authorization;

public sealed class SoteriaAdminAuthorizationHandler(SoteriaDbContext dbContext) : AuthorizationHandler<SoteriaAdminRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, SoteriaAdminRequirement requirement)
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

        var assignmentExists =
            await dbContext.UserSystemRoles
                .AsNoTracking()
                .AnyAsync(assignment => 
                    assignment.UserId == userId && 
                    assignment.SystemRoleId == SystemRoleIds.SoteriaAdministrator);

        if (assignmentExists)
        {
            context.Succeed(requirement);
        }
    }
}