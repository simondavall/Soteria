using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Soteria.Data.Authorization;
using Soteria.Data.OpenIddict;

namespace Soteria.Data;

public class SoteriaDbContext(DbContextOptions<SoteriaDbContext> options)
    : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>(options)
{
    // todo: need a discussion about this hard coded guid.
    private static readonly Guid SoteriaAdministratorRoleId =
        Guid.Parse("6f8ad0a0-72c2-4b82-bcc1-12a0e40b3508");

    public DbSet<SystemRole> SystemRoles => Set<SystemRole>();

    public DbSet<UserSystemRole> UserSystemRoles => Set<UserSystemRole>();

    public DbSet<ClientMembership> ClientMemberships => Set<ClientMembership>();

    public DbSet<ApplicationRole> ApplicationRoles => Set<ApplicationRole>();

    public DbSet<ClientMembershipApplicationRole> ClientMembershipApplicationRoles =>
        Set<ClientMembershipApplicationRole>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.UseOpenIddict<
            SoteriaApplication,
            SoteriaAuthorization,
            SoteriaScope,
            SoteriaToken,
            Guid>();

        ConfigureSoteriaApplication(builder);
        ConfigureSystemRole(builder);
        ConfigureUserSystemRole(builder);
        ConfigureClientMembership(builder);
        ConfigureApplicationRole(builder);
        ConfigureClientMembershipApplicationRole(builder);
    }

    private static void ConfigureSoteriaApplication(ModelBuilder builder)
    {
        builder.Entity<SoteriaApplication>(application =>
        {
            application.Property(item => item.IsEnabled)
                .HasDefaultValue(true);
        });
    }

    private static void ConfigureSystemRole(ModelBuilder builder)
    {
        builder.Entity<SystemRole>(role =>
        {
            role.ToTable("SystemRoles");

            role.HasKey(item => item.Id);

            role.Property(item => item.Name)
                .HasMaxLength(100)
                .IsRequired();

            role.Property(item => item.DisplayName)
                .HasMaxLength(200)
                .IsRequired();

            role.Property(item => item.Description)
                .HasMaxLength(500);

            role.HasIndex(item => item.Name)
                .IsUnique();

            role.HasData(new SystemRole
            {
                Id = SoteriaAdministratorRoleId,
                Name = "SoteriaAdministrator",
                DisplayName = "Soteria Administrator",
                Description = "Provides global administrative authority within Soteria."
            });
        });
    }

    private static void ConfigureUserSystemRole(ModelBuilder builder)
    {
        builder.Entity<UserSystemRole>(assignment =>
        {
            assignment.ToTable("UserSystemRoles");

            assignment.HasKey(item => new
            {
                item.UserId,
                item.SystemRoleId
            });

            assignment.HasOne(item => item.User)
                .WithMany(user => user.UserSystemRoles)
                .HasForeignKey(item => item.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            assignment.HasOne(item => item.SystemRole)
                .WithMany(role => role.UserSystemRoles)
                .HasForeignKey(item => item.SystemRoleId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }

    private static void ConfigureClientMembership(ModelBuilder builder)
    {
        builder.Entity<ClientMembership>(membership =>
        {
            membership.ToTable("ClientMemberships");

            membership.HasKey(item => item.Id);

            membership.HasAlternateKey(item => new
            {
                item.Id,
                item.ApplicationId
            });

            membership.Property(item => item.MembershipLevel)
                .HasConversion<string>()
                .HasMaxLength(50)
                .IsRequired();

            membership.Property(item => item.CreatedUtc)
                .IsRequired();

            membership.HasIndex(item => new
            {
                item.UserId,
                item.ApplicationId
            }).IsUnique();

            membership.HasOne(item => item.User)
                .WithMany(user => user.ClientMemberships)
                .HasForeignKey(item => item.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            membership.HasOne(item => item.Application)
                .WithMany(application => application.ClientMemberships)
                .HasForeignKey(item => item.ApplicationId)
                .OnDelete(DeleteBehavior.Restrict);
        });
    }

    private static void ConfigureApplicationRole(ModelBuilder builder)
    {
        builder.Entity<ApplicationRole>(role =>
        {
            role.ToTable("ApplicationRoles");

            role.HasKey(item => item.Id);

            role.HasAlternateKey(item => new
            {
                item.Id,
                item.ApplicationId
            });

            role.Property(item => item.Name)
                .HasMaxLength(200)
                .IsRequired();

            role.Property(item => item.DisplayName)
                .HasMaxLength(200)
                .IsRequired();

            role.Property(item => item.Description)
                .HasMaxLength(500);

            role.HasIndex(item => new
            {
                item.ApplicationId,
                item.Name
            }).IsUnique();

            role.HasOne(item => item.Application)
                .WithMany(application => application.ApplicationRoles)
                .HasForeignKey(item => item.ApplicationId)
                .OnDelete(DeleteBehavior.Restrict);
        });
    }

    private static void ConfigureClientMembershipApplicationRole(ModelBuilder builder)
    {
        builder.Entity<ClientMembershipApplicationRole>(assignment =>
        {
            assignment.ToTable("ClientMembershipApplicationRoles");

            assignment.Property<Guid>("ApplicationId");

            assignment.HasKey(item => new
            {
                item.ClientMembershipId,
                item.ApplicationRoleId
            });

            assignment.HasOne(item => item.ClientMembership)
                .WithMany(membership => membership.ApplicationRoleAssignments)
                .HasForeignKey(
                    nameof(ClientMembershipApplicationRole.ClientMembershipId),
                    "ApplicationId")
                .HasPrincipalKey(
                    nameof(ClientMembership.Id),
                    nameof(ClientMembership.ApplicationId))
                .OnDelete(DeleteBehavior.Cascade);

            assignment.HasOne(item => item.ApplicationRole)
                .WithMany(role => role.ClientMembershipAssignments)
                .HasForeignKey(
                    nameof(ClientMembershipApplicationRole.ApplicationRoleId),
                    "ApplicationId")
                .HasPrincipalKey(
                    nameof(ApplicationRole.Id),
                    nameof(ApplicationRole.ApplicationId))
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}