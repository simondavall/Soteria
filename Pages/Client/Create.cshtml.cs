#nullable disable

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.ComponentModel.DataAnnotations;

namespace Soteria.Pages.Client;

public class CreateClientModel : PageModel
{
    private readonly IOpenIddictApplicationManager _manager;

    public CreateClientModel(IOpenIddictApplicationManager manager)
    {
        _manager = manager;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();
    public string ReturnUrl { get; set; } = "/"; 

    public class InputModel
    {
        [Required]
        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        [Required]
        public string DisplayName { get; set; }

        [Required]
        public string RedirectUri { get; set; }

        public string PostLogoutRedirectUri { get; set; }
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
            return Page();

        var existing = await _manager.FindByClientIdAsync(Input.ClientId);

        if (existing != null)
        {
            ModelState.AddModelError("", "Client already exists.");
            return Page();
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = Input.ClientId,
            ClientSecret = Input.ClientSecret,
            DisplayName = Input.DisplayName,
            ConsentType = ConsentTypes.Explicit
        };

        descriptor.RedirectUris.Add(new Uri(Input.RedirectUri));

        if (!string.IsNullOrWhiteSpace(Input.PostLogoutRedirectUri))
        {
            descriptor.PostLogoutRedirectUris
                .Add(new Uri(Input.PostLogoutRedirectUri));
        }

        descriptor.Permissions.UnionWith(new[]
        {
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.EndSession,
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.GrantTypes.RefreshToken,
            Permissions.ResponseTypes.Code,
            Permissions.Scopes.Profile,
            Permissions.Scopes.Email,
            Permissions.Scopes.Roles
        });

        await _manager.CreateAsync(descriptor);

        TempData["Success"] = "Client created successfully.";
        return RedirectToPage();
    }
}

