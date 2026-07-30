using System.Globalization;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace Soteria.ReferenceWeb.Components.Authentication;

public sealed class AccessTokenManager(IOptionsMonitor<OpenIdConnectOptions> openIdConnectOptions, TimeProvider timeProvider)
{
    private static readonly TimeSpan RenewalWindow = TimeSpan.FromMinutes(1);

    public async Task<string> GetValidAccessTokenAsync(
        HttpContext context,
        bool forceRenewal = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var authenticationResult = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (!authenticationResult.Succeeded ||
            authenticationResult.Principal is null ||
            authenticationResult.Properties is null)
        {
            throw new AccessTokenRenewalException(
                "The local authentication session is unavailable.");
        }

        var properties = authenticationResult.Properties;

        var accessToken = properties.GetTokenValue("access_token");
        var refreshToken = properties.GetTokenValue("refresh_token");
        var expiresAtValue = properties.GetTokenValue("expires_at");
        
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            throw new AccessTokenRenewalException(
                "The local authentication session does not contain an access token.");
        }

        if (!forceRenewal && !RequiresRenewal(expiresAtValue))
        {
            return accessToken;
        }

        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            throw new AccessTokenRenewalException(
                "The local authentication session does not contain a refresh token.");
        }

        var tokenResponse = await RenewAccessTokenAsync(refreshToken, cancellationToken);
        PersistTokens(properties, tokenResponse, refreshToken);
        
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, authenticationResult.Principal, properties);
        return tokenResponse.AccessToken;
    }

    private bool RequiresRenewal(string? expiresAtValue)
    {
        if (string.IsNullOrWhiteSpace(expiresAtValue))
        {
            return true;
        }

        if (!DateTimeOffset.TryParse(
                expiresAtValue,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out var expiresAt))
        {
            return true;
        }

        return expiresAt <= timeProvider.GetUtcNow().Add(RenewalWindow);
    }

    private async Task<TokenResponse> RenewAccessTokenAsync(string refreshToken, CancellationToken cancellationToken)
    {
        var options = openIdConnectOptions.Get(OpenIdConnectDefaults.AuthenticationScheme);
        var configuration = options.Configuration;
        if (configuration is null)
        {
            var configurationManager = options.ConfigurationManager
                ?? throw new AccessTokenRenewalException(
                    "The OpenID Connect configuration manager is unavailable.");

            configuration = await configurationManager.GetConfigurationAsync(cancellationToken);
        }

        if (string.IsNullOrWhiteSpace(configuration.TokenEndpoint))
        {
            throw new AccessTokenRenewalException(
                "The OpenID Connect token endpoint is unavailable.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, configuration.TokenEndpoint);
        request.Content = new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = refreshToken,
                ["client_id"] = options.ClientId!,
                ["client_secret"] = options.ClientSecret!
            });

        using var response = await options.Backchannel.SendAsync(request, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync(cancellationToken);
            throw new AccessTokenRenewalException(
                $"The refresh-token exchange failed with status " +
                $"{(int)response.StatusCode}: {error}");
        }

        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken);
        if (tokenResponse is null ||
            string.IsNullOrWhiteSpace(tokenResponse.AccessToken) ||
            tokenResponse.ExpiresIn <= 0)
        {
            throw new AccessTokenRenewalException(
                "Soteria returned an invalid refresh-token response.");
        }

        return tokenResponse;
    }

    private void PersistTokens(AuthenticationProperties properties, TokenResponse response, string existingRefreshToken)
    {
        var tokens = properties.GetTokens().ToList();

        SetToken(tokens, "access_token", response.AccessToken);

        SetToken(
            tokens,
            "refresh_token",
            string.IsNullOrWhiteSpace(response.RefreshToken)
                ? existingRefreshToken
                : response.RefreshToken);

        var expiresAt = timeProvider
            .GetUtcNow()
            .AddSeconds(response.ExpiresIn)
            .ToString("o", CultureInfo.InvariantCulture);

        SetToken(tokens, "expires_at", expiresAt);

        properties.StoreTokens(tokens);
    }

    private static void SetToken(ICollection<AuthenticationToken> tokens, string name, string value)
    {
        var existingToken = tokens.FirstOrDefault(token => string.Equals(token.Name, name, StringComparison.Ordinal));
        if (existingToken is null)
        {
            tokens.Add(
                new AuthenticationToken
                {
                    Name = name,
                    Value = value
                });

            return;
        }

        existingToken.Value = value;
    }

    private sealed class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; init; } = string.Empty;

        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; init; }

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; init; }
    }
}

public sealed class AccessTokenRenewalException(string message, Exception? innerException = null) 
    : Exception(message, innerException);