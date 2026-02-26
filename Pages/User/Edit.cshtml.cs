#nullable disable

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Soteria.Models;

namespace Soteria.Pages.User;

public class EditUserModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<ApplicationRole> _roleManager;

    public EditUserModel(
        UserManager<ApplicationUser> userManager,
        RoleManager<ApplicationRole> roleManager)
    {
        _userManager = userManager;
        _roleManager = roleManager;
    }

    [BindProperty]
    public string UserId { get; set; }

    public string Email { get; set; }
    public string UserName { get; set; }

    [BindProperty]
    public List<RoleSelection> Roles { get; set; } = new();

    [TempData]
    public string StatusMessage { get; set; }

    public class RoleSelection
    {
        public string RoleName { get; set; }
        public bool Selected { get; set; }
    }

    public async Task<IActionResult> OnGetAsync(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null)
            return NotFound("User not found.");

        UserId = user.Id.ToString();
        Email = user.Email;
        UserName = user.UserName;

        var userRoles = await _userManager.GetRolesAsync(user);
        var allRoles = _roleManager.Roles.Select(r => r.Name).ToList();

        Roles = allRoles
            .Select(role => new RoleSelection {
                RoleName = role,
                Selected = userRoles.Contains(role)
            })
            .ToList();

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var user = await _userManager.FindByIdAsync(UserId);
        if (user == null) {
            ModelState.AddModelError("", "User not found.");
            return Page();
        }

        var userRoles = await _userManager.GetRolesAsync(user);

        var selectedRoles = Roles
            .Where(r => r.Selected)
            .Select(r => r.RoleName)
            .ToList();

        var rolesToAdd = selectedRoles.Except(userRoles);
        var rolesToRemove = userRoles.Except(selectedRoles);

        if (rolesToAdd.Any())
            await _userManager.AddToRolesAsync(user, rolesToAdd);

        if (rolesToRemove.Any())
            await _userManager.RemoveFromRolesAsync(user, rolesToRemove);
// todo-sdv: Need to wrap in try catch and report errors
        StatusMessage = "User roles updated successfully.";

        return RedirectToPage(new { id = UserId });
    }
}
