using Microsoft.AspNetCore.Identity;

namespace Soteria.Models;

public class ApplicationUser : IdentityUser<Guid>
{
  public string? DisplayName { get; set; }
}

