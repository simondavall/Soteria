using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Soteria.Data;

public class SoteriaDbContext(DbContextOptions<SoteriaDbContext> options)
    : IdentityDbContext<ApplicationUser>(options)
{
}