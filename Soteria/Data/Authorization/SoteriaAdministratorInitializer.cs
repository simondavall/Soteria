using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Soteria.Data.Authorization;

public sealed class SoteriaAdministratorInitializer(
    IServiceScopeFactory scopeFactory,
    IConfiguration configuration,
    ILogger<SoteriaAdministratorInitializer> logger)
{
    private const string AdministratorEmailConfigurationKey = "Bootstrap:SoteriaAdministratorEmail";

    private bool _bootstrapRegistrationRequired;

    public bool BootstrapRegistrationRequired => _bootstrapRegistrationRequired;

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var scope = scopeFactory.CreateAsyncScope();

        var dbContext = scope.ServiceProvider.GetRequiredService<SoteriaDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var roleExists = await dbContext.SystemRoles
            .AsNoTracking()
            .AnyAsync(role => role.Id == SystemRoleIds.SoteriaAdministrator, cancellationToken);

        if (!roleExists)
        {
            throw new InvalidOperationException(
                "The Soteria Administrator system role could not be found. " +
                "Ensure the database is using the latest migration.");
        }

        var administratorExists = await dbContext.UserSystemRoles
            .AsNoTracking()
            .AnyAsync(assignment => assignment.SystemRoleId == SystemRoleIds.SoteriaAdministrator, cancellationToken);

        if (administratorExists)
        {
            BootstrapCompleted();
            return;
        }

        var administratorEmail =
            configuration[AdministratorEmailConfigurationKey];

        if (string.IsNullOrWhiteSpace(administratorEmail))
        {
            RequireBootstrapRegistration();

            logger.LogInformation(
                "No Soteria Administrator exists and no bootstrap email " +
                "is configured. The first registered user will become " +
                "the Soteria Administrator.");

            return;
        }

        administratorEmail = administratorEmail.Trim();

        var user = await userManager.FindByEmailAsync(administratorEmail);
        if (user is null)
        {
            RequireBootstrapRegistration();

            logger.LogInformation(
                "No Identity user exists with the configured bootstrap " +
                "email '{AdministratorEmail}'. The first registered user " +
                "will become the Soteria Administrator.",
                administratorEmail);

            return;
        }

        dbContext.UserSystemRoles.Add(new UserSystemRole
        {
            UserId = user.Id,
            SystemRoleId = SystemRoleIds.SoteriaAdministrator
        });

        await dbContext.SaveChangesAsync(cancellationToken);
        BootstrapCompleted();

        logger.LogInformation(
            "Assigned the Soteria Administrator System Role to the " +
            "configured bootstrap user '{AdministratorEmail}'.",
            administratorEmail);
    }

    public void BootstrapCompleted()
    {
        _bootstrapRegistrationRequired = false;
    }

    private void RequireBootstrapRegistration()
    {
        _bootstrapRegistrationRequired = true;
    }
}