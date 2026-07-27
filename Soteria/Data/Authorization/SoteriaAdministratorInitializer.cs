using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Soteria.Data.Authorization;

public sealed class SoteriaAdministratorInitializer(
    SoteriaDbContext dbContext,
    UserManager<ApplicationUser> userManager,
    IConfiguration configuration)
{
    private const string AdministratorEmailConfigurationKey = "Bootstrap:SoteriaAdministratorEmail";

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        var administratorEmail = configuration[AdministratorEmailConfigurationKey];
        if (string.IsNullOrWhiteSpace(administratorEmail))
        {
            throw new InvalidOperationException(
                $"The {AdministratorEmailConfigurationKey} configuration value is required.");
        }

        administratorEmail = administratorEmail.Trim();

        var user = await userManager.FindByEmailAsync(administratorEmail);
        if (user is null)
        {
            throw new InvalidOperationException(
                "The configured Soteria Administrator user could not be found. " +
                $"No Identity user exists with the email '{administratorEmail}'.");
        }

        var roleExists = await dbContext.SystemRoles
            .AnyAsync(
                role => role.Id == SystemRoleIds.SoteriaAdministrator,
                cancellationToken);

        if (!roleExists)
        {
            throw new InvalidOperationException(
                "The Soteria Administrator system role could not be found. " +
                "Ensure the database is using the latest migration.");
        }

        var assignmentExists = await dbContext.UserSystemRoles
            .AnyAsync(
                assignment =>
                    assignment.UserId == user.Id &&
                    assignment.SystemRoleId ==
                    SystemRoleIds.SoteriaAdministrator,
                cancellationToken);

        if (assignmentExists)
        {
            return;
        }

        dbContext.UserSystemRoles.Add(new UserSystemRole
        {
            UserId = user.Id,
            SystemRoleId = SystemRoleIds.SoteriaAdministrator
        });

        await dbContext.SaveChangesAsync(cancellationToken);
    }
}