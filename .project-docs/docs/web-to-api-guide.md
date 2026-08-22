# Soteria Web Application to Web API Setup

## 1. Purpose

This document defines the minimum setup required for a Soteria-authenticated
ASP.NET Core web application to call a protected web API using the access token
issued by Soteria.

The web application:

* retrieves the access token from its local authentication session;
* renews the token using the refresh token when required;
* sends the access token to the API as a bearer token; and
* removes the local session if token renewal is no longer possible.

This document assumes that the web application is already configured to
authenticate through Soteria and that OpenID Connect token persistence is
enabled using:

```csharp
options.SaveTokens = true;
```

---

## 2. Application Configuration

Add the API base URL to the application configuration.

```json
{
  "ReferenceApi": {
    "BaseUrl": "https://localhost:7277"
  }
}
```

Replace `ReferenceApi` and the URL with values appropriate for the consuming
application and target API.

Read and validate the configuration during startup:

```csharp
var apiBaseUrl = builder.Configuration["ReferenceApi:BaseUrl"]
                 ?? throw new InvalidOperationException(
                     "The ReferenceApi:BaseUrl configuration value is required.");
```

Register a named HTTP client:

```csharp
builder.Services.AddHttpClient(
    "ReferenceApi",
    client =>
    {
        client.BaseAddress = new Uri(apiBaseUrl);
    });
```

Register the access-token service:

```csharp
builder.Services.AddScoped<AccessTokenManager>();
```

---

## 3. Access-Token Management

Add an `AccessTokenManager` to the web application.

The service:

* reads the current access token from the authentication cookie;
* checks the stored expiry time;
* renews the access token shortly before expiry;
* persists a replacement access token;
* persists a rotated refresh token when one is returned; and
* updates the local authentication cookie.

```csharp
using System.Globalization;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace ConsumerWeb.Authentication;

public sealed class AccessTokenManager(
    IOptionsMonitor<OpenIdConnectOptions> openIdConnectOptions,
    TimeProvider timeProvider)
{
    private static readonly TimeSpan RenewalWindow = TimeSpan.FromMinutes(1);

    public async Task<string> GetValidAccessTokenAsync(
        HttpContext context,
        bool forceRenewal = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var authenticationResult =
            await context.AuthenticateAsync(
                CookieAuthenticationDefaults.AuthenticationScheme);

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

        var tokenResponse =
            await RenewAccessTokenAsync(
                refreshToken,
                cancellationToken);

        PersistTokens(
            properties,
            tokenResponse,
            refreshToken);

        await context.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            authenticationResult.Principal,
            properties);

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

        return expiresAt <=
               timeProvider.GetUtcNow().Add(RenewalWindow);
    }

    private async Task<TokenResponse> RenewAccessTokenAsync(
        string refreshToken,
        CancellationToken cancellationToken)
    {
        var options =
            openIdConnectOptions.Get(
                OpenIdConnectDefaults.AuthenticationScheme);

        var configuration = options.Configuration;

        if (configuration is null)
        {
            var configurationManager =
                options.ConfigurationManager
                ?? throw new AccessTokenRenewalException(
                    "The OpenID Connect configuration manager is unavailable.");

            configuration =
                await configurationManager.GetConfigurationAsync(
                    cancellationToken);
        }

        if (string.IsNullOrWhiteSpace(configuration.TokenEndpoint))
        {
            throw new AccessTokenRenewalException(
                "The OpenID Connect token endpoint is unavailable.");
        }

        using var request =
            new HttpRequestMessage(
                HttpMethod.Post,
                configuration.TokenEndpoint);

        request.Content =
            new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["refresh_token"] = refreshToken,
                    ["client_id"] = options.ClientId!,
                    ["client_secret"] = options.ClientSecret!
                });

        using var response =
            await options.Backchannel.SendAsync(
                request,
                cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var error =
                await response.Content.ReadAsStringAsync(
                    cancellationToken);

            throw new AccessTokenRenewalException(
                $"The refresh-token exchange failed with status " +
                $"{(int)response.StatusCode}: {error}");
        }

        var tokenResponse =
            await response.Content.ReadFromJsonAsync<TokenResponse>(
                cancellationToken);

        if (tokenResponse is null ||
            string.IsNullOrWhiteSpace(tokenResponse.AccessToken) ||
            tokenResponse.ExpiresIn <= 0)
        {
            throw new AccessTokenRenewalException(
                "Soteria returned an invalid refresh-token response.");
        }

        return tokenResponse;
    }

    private void PersistTokens(
        AuthenticationProperties properties,
        TokenResponse response,
        string existingRefreshToken)
    {
        var tokens = properties.GetTokens().ToList();

        SetToken(
            tokens,
            "access_token",
            response.AccessToken);

        SetToken(
            tokens,
            "refresh_token",
            string.IsNullOrWhiteSpace(response.RefreshToken)
                ? existingRefreshToken
                : response.RefreshToken);

        var expiresAt =
            timeProvider
                .GetUtcNow()
                .AddSeconds(response.ExpiresIn)
                .ToString("o", CultureInfo.InvariantCulture);

        SetToken(
            tokens,
            "expires_at",
            expiresAt);

        properties.StoreTokens(tokens);
    }

    private static void SetToken(
        ICollection<AuthenticationToken> tokens,
        string name,
        string value)
    {
        var existingToken =
            tokens.FirstOrDefault(
                token => string.Equals(
                    token.Name,
                    name,
                    StringComparison.Ordinal));

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

public sealed class AccessTokenRenewalException(
    string message,
    Exception? innerException = null)
    : Exception(message, innerException);
```

The one-minute renewal window avoids sending an access token that is close to
expiry. The implementation also supports rolling refresh-token replacement by
persisting the replacement refresh token returned by Soteria.

---

## 4. Call the API

The API call should be performed on the server rather than directly from the
browser.

Create an authenticated internal endpoint in the web application.

```csharp
using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using ConsumerWeb.Authentication;

namespace Microsoft.AspNetCore.Routing;

internal static class ApiEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapApiEndpoint(
        this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints
            .MapGet(
                "/internal/api/example",
                HandleApiRequestAsync)
            .RequireAuthorization();
    }

    private static async Task<IResult> HandleApiRequestAsync(
        HttpContext context,
        IHttpClientFactory httpClientFactory,
        AccessTokenManager accessTokenManager)
    {
        try
        {
            var accessToken =
                await accessTokenManager.GetValidAccessTokenAsync(
                    context,
                    cancellationToken: context.RequestAborted);

            var response =
                await CallApiAsync(
                    httpClientFactory,
                    "/api/example",
                    accessToken,
                    context.RequestAborted);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                response.Dispose();

                accessToken =
                    await accessTokenManager.GetValidAccessTokenAsync(
                        context,
                        forceRenewal: true,
                        cancellationToken: context.RequestAborted);

                response =
                    await CallApiAsync(
                        httpClientFactory,
                        "/api/example",
                        accessToken,
                        context.RequestAborted);
            }

            using (response)
            {
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    return Results.Json(
                        new ApiError(
                            "The API rejected the renewed access token."),
                        statusCode:
                            StatusCodes.Status401Unauthorized);
                }

                if (!response.IsSuccessStatusCode)
                {
                    return Results.Json(
                        new ApiError(
                            $"The API returned status " +
                            $"{(int)response.StatusCode}."),
                        statusCode: (int)response.StatusCode);
                }

                var responseContent =
                    await response.Content.ReadAsStringAsync(
                        context.RequestAborted);

                if (string.IsNullOrWhiteSpace(responseContent))
                {
                    return Results.Json(
                        new ApiError(
                            "The API returned an empty response."),
                        statusCode:
                            StatusCodes.Status502BadGateway);
                }

                var contentType =
                    response.Content.Headers.ContentType?.ToString()
                    ?? "application/json";

                return Results.Content(
                    responseContent,
                    contentType,
                    statusCode: StatusCodes.Status200OK);
            }
        }
        catch (AccessTokenRenewalException)
        {
            await context.SignOutAsync(
                CookieAuthenticationDefaults.AuthenticationScheme);

            return Results.Json(
                new ApiError(
                    "The local authentication session has expired."),
                statusCode:
                    StatusCodes.Status401Unauthorized);
        }
        catch (HttpRequestException exception)
        {
            return Results.Json(
                new ApiError(
                    $"The API request failed: {exception.Message}"),
                statusCode:
                    StatusCodes.Status502BadGateway);
        }
    }

    private static async Task<HttpResponseMessage> CallApiAsync(
        IHttpClientFactory httpClientFactory,
        string apiEndpointPath,
        string accessToken,
        CancellationToken cancellationToken)
    {
        var httpClient =
            httpClientFactory.CreateClient("ReferenceApi");

        using var request =
            new HttpRequestMessage(
                HttpMethod.Get,
                apiEndpointPath);

        request.Headers.Authorization =
            new AuthenticationHeaderValue(
                "Bearer",
                accessToken);

        return await httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
    }

    private sealed record ApiError(string Message);
}
```

This endpoint performs the following sequence:

1. Obtain a valid access token.
2. Send the token using the HTTP `Authorization` header.
3. If the API returns `401`, force a token renewal.
4. Retry the API request once.
5. If renewal fails, remove the local authentication cookie.
6. Return the API result to the browser.

The retry should occur only once. A second `401` indicates that the renewed
token was rejected and should be returned to the client as an authentication
failure.

---

## 5. Register the Endpoint

Map the internal endpoint during application startup:

```csharp
app.MapApiEndpoint();
```

The endpoint must be mapped after authentication and authorisation middleware
have been added:

```csharp
app.UseAuthentication();
app.UseAuthorization();

app.MapApiEndpoint();
```

Because the endpoint uses:

```csharp
.RequireAuthorization();
```

only authenticated users can cause the web application to call the protected
API.

---

## 6. Browser Call

The application UI should call the web application's internal endpoint:

```text
/internal/api/example
```

It should not send the Soteria access token from browser code.

Example JavaScript:

```javascript
export async function callApi() {
    const response = await fetch("/internal/api/example", {
        method: "GET",
        credentials: "same-origin"
    });

    const content = await response.json();

    return {
        ok: response.ok,
        status: response.status,
        data: response.ok ? content : null,
        message: response.ok ? null : content.message
    };
}
```

The browser sends only the web application's local authentication cookie. The
server retrieves and sends the Soteria access token to the API.

---

## 7. Verification

Verify the following after completing the setup:

* [ ] The user can authenticate through Soteria.
* [ ] The local authentication session contains an access token.
* [ ] The local authentication session contains a refresh token.
* [ ] The internal API endpoint requires authentication.
* [ ] The web application sends the access token using the bearer authentication scheme.
* [ ] The protected API accepts the access token.
* [ ] The API receives the expected user and role claims.
* [ ] An expired access token is renewed automatically.
* [ ] A replacement refresh token is persisted.
* [ ] An API `401` triggers one forced renewal and retry.
* [ ] Failed token renewal removes the local authentication session.
* [ ] The access token is never exposed to browser code.
