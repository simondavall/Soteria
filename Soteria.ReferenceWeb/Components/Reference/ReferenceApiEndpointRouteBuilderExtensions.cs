using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Soteria.ReferenceWeb.Components.Authentication;
using Soteria.ReferenceWeb.Components.Reference;

// ReSharper disable CheckNamespace

namespace Microsoft.AspNetCore.Routing;

internal static class ReferenceApiEndpointRouteBuilderExtensions
{
    public static IEndpointConventionBuilder MapReferenceApiEndpoint(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        return endpoints
            .MapGet("/internal/reference-api", HandleReferenceApiRequestAsync)
            .RequireAuthorization();
    }

    private static async Task<IResult> HandleReferenceApiRequestAsync(
        HttpContext context,
        IHttpClientFactory httpClientFactory,
        AccessTokenManager accessTokenManager)
    {
        try
        {
            var accessToken = await accessTokenManager.GetValidAccessTokenAsync(context, cancellationToken: context.RequestAborted);
            var response = await CallReferenceApiAsync(httpClientFactory, accessToken, context.RequestAborted);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                response.Dispose();
                accessToken = await accessTokenManager.GetValidAccessTokenAsync(context, forceRenewal: true, cancellationToken: context.RequestAborted);
                response = await CallReferenceApiAsync(httpClientFactory, accessToken, context.RequestAborted);
            }

            using (response)
            {
                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    return Results.Json(
                        new ReferenceApiResult(
                            "The Reference API rejected the renewed access token."),
                        statusCode: StatusCodes.Status401Unauthorized);
                }

                if (!response.IsSuccessStatusCode)
                {
                    return Results.Json(
                        new ReferenceApiResult(
                            $"The Reference API returned status " +
                            $"{(int)response.StatusCode}."),
                        statusCode: (int)response.StatusCode);
                }

                var referenceResponse = await response.Content.ReadFromJsonAsync<ReferenceResponse>(context.RequestAborted);
                
                return Results.Ok(new ReferenceApiResult(referenceResponse?.Message ?? "The Reference API returned an empty response."));
            }
        }
        catch (AccessTokenRenewalException)
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Results.Json(
                new ReferenceApiResult(
                    "The local authentication session has expired."),
                statusCode: StatusCodes.Status401Unauthorized);
        }
        catch (HttpRequestException exception)
        {
            return Results.Json(
                new ReferenceApiResult(
                    $"The Reference API request failed: {exception.Message}"),
                statusCode: StatusCodes.Status502BadGateway);
        }
        catch (NotSupportedException exception)
        {
            return Results.Json(
                new ReferenceApiResult(
                    $"The Reference API returned an unsupported response: " +
                    exception.Message),
                statusCode: StatusCodes.Status502BadGateway);
        }
        catch (System.Text.Json.JsonException exception)
        {
            return Results.Json(
                new ReferenceApiResult(
                    $"The Reference API returned invalid JSON: " +
                    exception.Message),
                statusCode: StatusCodes.Status502BadGateway);
        }
    }

    private static async Task<HttpResponseMessage> CallReferenceApiAsync(
        IHttpClientFactory httpClientFactory,
        string accessToken,
        CancellationToken cancellationToken)
    {
        var httpClient = httpClientFactory.CreateClient("ReferenceApi");

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            "/api/reference");

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);

        return await httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
    }

    private sealed record ReferenceApiResult(string Message);
}