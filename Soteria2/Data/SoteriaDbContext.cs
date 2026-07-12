using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Soteria2.Data;

public class SoteriaDbContext(DbContextOptions<SoteriaDbContext> options)
    : IdentityDbContext<ApplicationUser>(options)
{
}