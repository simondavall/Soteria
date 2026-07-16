using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Soteria.Data;
// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Account.Pages.Manage;

public partial class Index
{
    private ApplicationUser _user = null!;
    private string? _username;
    private string? _phoneNumber;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private SignInManager<ApplicationUser> SignInManager { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = null!;
    [SupplyParameterFromForm] private InputModel Input { get; set; } = null!;

    protected override async Task OnInitializedAsync()
    {
        // this is needed, even though non-nullable
        Input ??= new InputModel();

        var user = await UserManager.GetUserAsync(HttpContext.User);
        if (user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        _user = user;
        _username = await UserManager.GetUserNameAsync(_user);
        _phoneNumber = await UserManager.GetPhoneNumberAsync(_user);

        if (HttpMethods.IsGet(HttpContext.Request.Method))
        {
            Input.PhoneNumber = _phoneNumber;
        }
    }

    private async Task OnValidSubmitAsync()
    {
        if (Input.PhoneNumber != _phoneNumber)
        {
            var setPhoneResult = await UserManager.SetPhoneNumberAsync(_user, Input.PhoneNumber);
            if (!setPhoneResult.Succeeded)
            {
                RedirectManager.RedirectToCurrentPageWithStatus("Error: Failed to set phone number.", HttpContext);
                return;
            }
        }

        await SignInManager.RefreshSignInAsync(_user);

        RedirectManager.RedirectToCurrentPageWithStatus("Your profile has been updated.", HttpContext);
    }

    private sealed class InputModel
    {
        // Do not replace with 'field', it doesn't work.
        private string? _phoneNumber;

        [Phone]
        [Display(Name = "Phone number")]
        public string? PhoneNumber
        {
            get => _phoneNumber;

            set => _phoneNumber = string.IsNullOrWhiteSpace(value)
                ? null
                : value;
        }
    }
}