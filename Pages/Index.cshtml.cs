#nullable disable

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Soteria.Models;

namespace Soteria.Pages;

public struct ClientLink
{
    public string Name { get; set; }
    public string Link { get; set; }
}

public struct UserLink
{
    public string Email { get; set; }
    public string DisplayName { get; set; }
    public string Link { get; set; }
}

public class IndexModel : PageModel
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public IndexModel(IOpenIddictApplicationManager manager, UserManager<ApplicationUser> userManager)
    {
        _applicationManager = manager;
        _userManager = userManager;
    }

    public List<ClientLink> ClientLinks { get; set; } = [];
    public List<UserLink> UserLinks { get; set; } = [];

    public async Task OnGet()
    {
        await foreach (var application in _applicationManager.ListAsync()) {
            var clientId = await _applicationManager.GetClientIdAsync(application);
            var displayName = await _applicationManager.GetDisplayNameAsync(application);

            ClientLinks.Add(new ClientLink { Name = displayName, Link = $"/Client/Edit/{clientId}" });
        }
        var users = await _userManager.Users.ToListAsync();
        foreach (var user in users) {
            UserLinks.Add(new UserLink { Email = user.Email, DisplayName = user.DisplayName, Link = $"/User/Edit/{user.Id}" });
        }
    }
}
