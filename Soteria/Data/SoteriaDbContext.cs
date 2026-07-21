using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Soteria.Data.OpenIddict;

namespace Soteria.Data;

public class SoteriaDbContext(DbContextOptions<SoteriaDbContext> options)
    : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>(options)
{
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.UseOpenIddict<
            SoteriaApplication,
            SoteriaAuthorization,
            SoteriaScope,
            SoteriaToken,
            Guid>();

        builder.Entity<SoteriaApplication>()
            .Property(application => application.IsEnabled)
            .HasDefaultValue(true);
    }
}