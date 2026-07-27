using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Soteria.ReferenceWeb.Components.Authentication;

// ReSharper disable CheckNamespace

namespace Microsoft.AspNetCore.Routing;

internal static class ReferenceApiEndpointRouteBuilderExtensions
{
    private static readonly IReadOnlyDictionary<string, string> ApiEndpointPaths =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["reference"] = "/api/reference",
            ["editor"] = "/api/editor",
            ["auditor"] = "/api/auditor",
            ["review"] = "/api/review",
            ["claims"] = "/api/claims"
        };

    public static IEndpointConventionBuilder MapReferenceApiEndpoint(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints
            .MapGet("/internal/reference-api/{endpoint}", HandleReferenceApiRequestAsync)
            .RequireAuthorization();
    }

    private static async Task<IResult> HandleReferenceApiRequestAsync(
        string endpoint,
        HttpContext context,
        IHttpClientFactory httpClientFactory,
        AccessTokenManager accessTokenManager)
    {
        if (!ApiEndpointPaths.TryGetValue(endpoint, out var apiEndpointPath))
        {
            return Results.NotFound(
                new ReferenceApiError($"The Reference API endpoint '{endpoint}' is not supported."));
        }

        try
        {
            var accessToken = await accessTokenManager.GetValidAccessTokenAsync(context, 
                cancellationToken: context.RequestAborted);
            var response = await CallReferenceApiAsync(httpClientFactory, apiEndpointPath, accessToken,
                context.RequestAborted);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                response.Dispose();

                accessToken = await accessTokenManager.GetValidAccessTokenAsync(context, forceRenewal: true,
                    cancellationToken: context.RequestAborted);
                response = await CallReferenceApiAsync(httpClientFactory, apiEndpointPath, accessToken,
                    context.RequestAborted);
            }

            using (response)
            {
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    return Results.Json(new ReferenceApiError("The Reference API rejected the renewed access token."),
                        statusCode: StatusCodes.Status401Unauthorized);
                }

                if (!response.IsSuccessStatusCode)
                {
                    return Results.Json(
                        new ReferenceApiError($"The Reference API returned status {(int)response.StatusCode}."),
                        statusCode: (int)response.StatusCode);
                }

                var responseContent = await response.Content.ReadAsStringAsync(context.RequestAborted);
                if (string.IsNullOrWhiteSpace(responseContent))
                {
                    return Results.Json(new ReferenceApiError("The Reference API returned an empty response."),
                        statusCode: StatusCodes.Status502BadGateway);
                }

                var contentType = response.Content.Headers.ContentType?.ToString() ?? "application/json";

                return Results.Content(responseContent, contentType, statusCode: StatusCodes.Status200OK);
            }
        }
        catch (AccessTokenRenewalException)
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Results.Json(new ReferenceApiError("The local authentication session has expired."),
                statusCode: StatusCodes.Status401Unauthorized);
        }
        catch (HttpRequestException exception)
        {
            return Results.Json(new ReferenceApiError($"The Reference API request failed: " + exception.Message),
                statusCode: StatusCodes.Status502BadGateway);
        }
    }

    private static async Task<HttpResponseMessage>
        CallReferenceApiAsync(
            IHttpClientFactory httpClientFactory,
            string apiEndpointPath,
            string accessToken,
            CancellationToken cancellationToken)
    {
        var httpClient = httpClientFactory.CreateClient("ReferenceApi");

        using var request = new HttpRequestMessage(HttpMethod.Get, apiEndpointPath);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        return await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
    }

    private sealed record ReferenceApiError(
        string Message);
}