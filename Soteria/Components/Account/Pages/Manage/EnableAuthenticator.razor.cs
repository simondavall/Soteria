using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;
using Net.Codecrete.QrCodeGenerator;
using Soteria.Data;
// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Account.Pages.Manage;

public partial class EnableAuthenticator
{
    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
    private const string AuthenticatorIssuer = "Soteria";

    private string? _message;
    private ApplicationUser? _user;
    private string? _sharedKey;
    private IEnumerable<string>? _recoveryCodes;
    private const int QrCodeQuietZone = 4;
    private MarkupString _qrCodeSvg;

    [Inject] private UserManager<ApplicationUser> UserManager { get; set; } = null!;
    [Inject] private UrlEncoder UrlEncoder { get; set; } = null!;
    [Inject] private IdentityRedirectManager RedirectManager { get; set; } = null!;
    [Inject] private ILogger<EnableAuthenticator> Logger { get; set; } = null!;

    [CascadingParameter] private HttpContext HttpContext { get; set; } = null!;
    [SupplyParameterFromForm] private InputModel Input { get; set; } = null!;

    protected override async Task OnInitializedAsync()
    {
        // this is needed, even though non-nullable
        Input ??= new InputModel();

        _user = await UserManager.GetUserAsync(HttpContext.User);
        if (_user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        await LoadSharedKeyAndQrCodeAsync(_user);
    }

    private async Task OnValidSubmitAsync()
    {
        if (_user is null)
        {
            RedirectManager.RedirectToInvalidUser(UserManager, HttpContext);
            return;
        }

        var verificationCode = Input.Code
            .Replace(" ", string.Empty)
            .Replace("-", string.Empty);

        var isTokenValid = await UserManager
            .VerifyTwoFactorTokenAsync(_user, UserManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

        if (!isTokenValid)
        {
            _message = "Error: Verification code is invalid.";
            return;
        }

        await UserManager.SetTwoFactorEnabledAsync(_user, true);
        var userId = await UserManager.GetUserIdAsync(_user);

        Logger.LogInformation("User with ID '{UserId}' enabled two-factor authentication.", userId);

        _message = "Your authenticator app has been verified.";
        if (await UserManager.CountRecoveryCodesAsync(_user) == 0)
        {
            _recoveryCodes = await UserManager.GenerateNewTwoFactorRecoveryCodesAsync(_user, 10);
        }
        else
        {
            RedirectManager.RedirectToWithStatus("Account/Manage/TwoFactorAuthentication", _message, HttpContext);
        }
    }

    private async Task LoadSharedKeyAndQrCodeAsync(ApplicationUser user)
    {
        var unformattedKey = await UserManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(unformattedKey))
        {
            await UserManager.ResetAuthenticatorKeyAsync(user);
            unformattedKey = await UserManager.GetAuthenticatorKeyAsync(user);
        }

        _sharedKey = FormatKey(unformattedKey!);

        var email = await UserManager.GetEmailAsync(user);
        var authenticatorUri = GenerateQrCodeUri(email!, unformattedKey!);

        var qrCode = QrCode.EncodeText(authenticatorUri, QrCode.Ecc.Medium);
        _qrCodeSvg = new MarkupString(qrCode.ToSvgString(QrCodeQuietZone));
    }

    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        var currentPosition = 0;

        while (currentPosition + 4 < unformattedKey.Length)
        {
            result
                .Append(unformattedKey.AsSpan(currentPosition, 4))
                .Append(' ');

            currentPosition += 4;
        }

        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }

    private string GenerateQrCodeUri(string email, string unformattedKey)
    {
        return string.Format(
            CultureInfo.InvariantCulture,
            AuthenticatorUriFormat,
            UrlEncoder.Encode(AuthenticatorIssuer),
            UrlEncoder.Encode(email),
            unformattedKey);
    }

    private sealed class InputModel
    {
        [Required]
        [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Text)]
        [Display(Name = "Verification code")]
        public string Code { get; set; } = string.Empty;
    }
}