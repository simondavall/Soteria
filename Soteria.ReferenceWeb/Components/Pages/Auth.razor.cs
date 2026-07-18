using System.Net.Http.Headers;
using Soteria.ReferenceWeb.Components.Reference;
using Microsoft.AspNetCore.Authentication;

namespace Soteria.ReferenceWeb.Components.Pages;

public partial class Auth(IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor)
{
    private bool isLoading;
    private string? responseMessage;
    private string? errorMessage;

    private async Task CallReferenceApiAsync()
    {
        isLoading = true;
        responseMessage = null;
        errorMessage = null;

        try
        {
            var httpContext = httpContextAccessor.HttpContext
                              ?? throw new InvalidOperationException(
                                  "The current HTTP context is unavailable.");

            var accessToken = await httpContext.GetTokenAsync("access_token");

            if (string.IsNullOrWhiteSpace(accessToken))
            {
                errorMessage = "The local authentication session does not contain an access token.";
                return;
            }
            var httpClient = httpClientFactory.CreateClient("ReferenceApi");
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            
            var response = await httpClient.GetFromJsonAsync<ReferenceResponse>("/api/reference");
            responseMessage = response?.Message ?? "The Reference API returned an empty response.";
        }
        catch (InvalidOperationException exception)
        {
            errorMessage = $"The authenticated session could not be accessed: {exception.Message}";
        }
        catch (HttpRequestException exception)
        {
            errorMessage = $"The Reference API request failed: {exception.Message}";
        }
        catch (NotSupportedException exception)
        {
            errorMessage = $"The Reference API returned an unsupported response: {exception.Message}";
        }
        catch (System.Text.Json.JsonException exception)
        {
            errorMessage = $"The Reference API returned invalid JSON: {exception.Message}";
        }
        finally
        {
            isLoading = false;
        }
    }
}