#nullable disable

using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace Soteria.Pages.Client;

[Authorize(Roles = "Admin")]
public class EditClientModel : PageModel
{
    private readonly IOpenIddictApplicationManager _applicationManager;

    public EditClientModel(IOpenIddictApplicationManager manager)
    {
        _applicationManager = manager;
    }

    [BindProperty]
    public string ApplicationId { get; set; }

    [Required]
    [BindProperty]
    public string ClientId { get; set; }

    [TempData]
    public string StatusMessage { get; set; }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public class InputModel
    {
        public string ClientSecret { get; set; }
        [Required]
        public string DisplayName { get; set; }
        [Required]
        public string RedirectUri { get; set; }
        public string PostLogoutRedirectUri { get; set; }
    }

    private async Task LoadAsync(object application)
    {
        OpenIddictApplicationDescriptor descriptor = new();
        await _applicationManager.PopulateAsync(descriptor, application);
        ApplicationId = await _applicationManager.GetIdAsync(application);
        ClientId = descriptor.ClientId;
        Input = new InputModel {
            DisplayName = descriptor.DisplayName,
            RedirectUri = descriptor.RedirectUris.FirstOrDefault()?.ToString(),
            PostLogoutRedirectUri = descriptor.PostLogoutRedirectUris.FirstOrDefault()?.ToString(),
        };
    }

    public async Task<IActionResult> OnGetAsync(string clientId)
    {
        object application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application is null)
            return NotFound($"Unable to load client with ID '{clientId}'.");

        await LoadAsync(application);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        object application = await _applicationManager.FindByIdAsync(ApplicationId);
        if (application == null) {
            ModelState.AddModelError("", "Client not found or tampered with.");
            return Page();
        }

        string currentClientId = await _applicationManager.GetClientIdAsync(application);
        if (currentClientId != ClientId) {
            ModelState.AddModelError("", "Client ID mismatch. Unauthorized modification.");
            return Page();
        }

        if (!ModelState.IsValid) {
            await LoadAsync(application);
            return Page();
        }

        OpenIddictApplicationDescriptor descriptor = new();
        await _applicationManager.PopulateAsync(descriptor, application);

        bool changesDetected = false;

        if (Input.DisplayName != descriptor.DisplayName) {
            descriptor.DisplayName = Input.DisplayName;
            changesDetected = true;
        }

        if (!string.IsNullOrWhiteSpace(Input.ClientSecret)) {
            descriptor.ClientSecret = Input.ClientSecret;
            changesDetected = true;
        }

        if (Input.RedirectUri != descriptor.RedirectUris.FirstOrDefault()?.ToString()) {
            descriptor.RedirectUris.Clear();
            descriptor.RedirectUris.Add(new Uri(Input.RedirectUri));
            changesDetected = true;
        }

        if (Input.PostLogoutRedirectUri != descriptor.PostLogoutRedirectUris.FirstOrDefault()?.ToString()) {
            descriptor.PostLogoutRedirectUris.Clear();
            if (!string.IsNullOrWhiteSpace(Input.PostLogoutRedirectUri)) {
                descriptor.PostLogoutRedirectUris.Add(new Uri(Input.PostLogoutRedirectUri));
            }
            changesDetected = true;
        }

        if (changesDetected) {
            await _applicationManager.UpdateAsync(application, descriptor);

            StatusMessage = "Your client profile has been updated";
        } else {

            StatusMessage = "No changes detected.";
        }
        return RedirectToPage();
    }
}

