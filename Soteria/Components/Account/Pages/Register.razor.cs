using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Soteria.Data;
using Soteria.Data.Authorization;
// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Account.Pages;

public partial class Register
{
    [Inject]
    private SoteriaDbContext DbContext { get; set; } = null!;
    [Inject]
    private SoteriaAdministratorInitializer SoteriaAdministratorInitializer { get; set; } = null!;
    [Inject]
    private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject]
    private IUserStore<ApplicationUser> UserStore { get; set; } = null!;
    [Inject]
    private SignInManager<ApplicationUser> SignInManager { get; set; } = null!;
    [Inject]
    private IEmailSender<ApplicationUser> EmailSender { get; set; } = null!;
    [Inject]
    private ILogger<Register> Logger { get; set; } = null!;
    [Inject]
    private NavigationManager NavigationManager { get; set; } = null!;
    [Inject]
    private IdentityRedirectManager RedirectManager { get; set; } = null!;

    [CascadingParameter]
    private HttpContext HttpContext { get; set; } = null!;
    [SupplyParameterFromForm]
    private InputModel Input { get; set; } = null!;
    [SupplyParameterFromQuery]
    private string? ReturnUrl { get; set; }

    private static readonly SemaphoreSlim BootstrapLock = new(1, 1);
    private IEnumerable<IdentityError>? _identityErrors;
    
    private string? Message => _identityErrors is null ? 
        null : 
        $"Error: {string.Join(", ", _identityErrors.Select(error => error.Description))}";

    protected override async Task OnInitializedAsync()
    {
        // This is needed, even though non-nullable.
        Input ??= new InputModel();

        if (await SoteriaAdministratorExistsAsync())
        {
            RedirectManager.RedirectTo("Account/Login");
        }
    }

    private async Task RegisterUserAsync()
    {
        await BootstrapLock.WaitAsync();

        try
        {
            if (await SoteriaAdministratorExistsAsync())
            {
                RedirectManager.RedirectTo("Account/Login");
                return;
            }

            await using var transaction = await DbContext.Database.BeginTransactionAsync(IsolationLevel.Serializable);

            try
            {
                // Recheck after beginning the transaction.
                if (await SoteriaAdministratorExistsAsync())
                {
                    await transaction.RollbackAsync();

                    RedirectManager.RedirectTo("Account/Login");
                    return;
                }

                var roleExists = await DbContext.SystemRoles
                    .AnyAsync(role => role.Id == SystemRoleIds.SoteriaAdministrator);

                if (!roleExists)
                {
                    throw new InvalidOperationException(
                        "The Soteria Administrator system role could not " +
                        "be found. Ensure the database is using the " +
                        "latest migration.");
                }

                var user = CreateUser();
                await UserStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);

                var emailStore = GetEmailStore();
                await emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);

                var result = await UserManager.CreateAsync(user, Input.Password);
                if (!result.Succeeded)
                {
                    await transaction.RollbackAsync();

                    _identityErrors = result.Errors;
                    return;
                }

                DbContext.UserSystemRoles.Add(new UserSystemRole
                {
                    UserId = user.Id,
                    SystemRoleId = SystemRoleIds.SoteriaAdministrator
                });

                await DbContext.SaveChangesAsync();
                await transaction.CommitAsync();

                SoteriaAdministratorInitializer.BootstrapCompleted();

                Logger.LogInformation(
                    "Created the initial Soteria user and assigned the " +
                    "Soteria Administrator System Role.");

                await SendConfirmationEmailAndRedirectAsync(user);
            }
            catch
            {
                await transaction.RollbackAsync();
                throw;
            }
        }
        finally
        {
            BootstrapLock.Release();
        }
    }

    private Task<bool> SoteriaAdministratorExistsAsync()
    {
        return DbContext.UserSystemRoles
            .AsNoTracking()
            .AnyAsync(assignment => assignment.SystemRoleId == SystemRoleIds.SoteriaAdministrator);
    }

    private async Task SendConfirmationEmailAndRedirectAsync(ApplicationUser user)
    {
        var userId = await UserManager.GetUserIdAsync(user);
        var code = await UserManager.GenerateEmailConfirmationTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var callbackUrl =
            NavigationManager.GetUriWithQueryParameters(
                NavigationManager
                    .ToAbsoluteUri("Account/ConfirmEmail")
                    .AbsoluteUri,
                new Dictionary<string, object?>
                {
                    ["userId"] = userId,
                    ["code"] = code,
                    ["returnUrl"] = ReturnUrl
                });

        await EmailSender.SendConfirmationLinkAsync(user, Input.Email, HtmlEncoder.Default.Encode(callbackUrl));

        if (UserManager.Options.SignIn.RequireConfirmedAccount)
        {
            RedirectManager.RedirectTo(
                "Account/RegisterConfirmation",
                new Dictionary<string, object?>
                {
                    ["email"] = Input.Email,
                    ["returnUrl"] = ReturnUrl
                });
        }
        else
        {
            await SignInManager.SignInAsync(user, isPersistent: false);
            RedirectManager.RedirectTo(ReturnUrl);
        }
    }

    private static ApplicationUser CreateUser()
    {
        try
        {
            return Activator.CreateInstance<ApplicationUser>();
        }
        catch
        {
            throw new InvalidOperationException(
                $"Can't create an instance of '{nameof(ApplicationUser)}'. Ensure that " +
                $"'{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor.");
        }
    }

    private IUserEmailStore<ApplicationUser> GetEmailStore()
    {
        if (!UserManager.SupportsUserEmail)
        {
            throw new NotSupportedException(
                "The default UI requires a user store with email support.");
        }

        return (IUserEmailStore<ApplicationUser>)UserStore;
    }

    private sealed class InputModel
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare(nameof(Password), ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}