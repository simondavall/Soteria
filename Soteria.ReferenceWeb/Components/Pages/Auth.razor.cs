using Soteria.ReferenceWeb.Components.Reference;

namespace Soteria.ReferenceWeb.Components.Pages;

public partial class Auth(IHttpClientFactory httpClientFactory)
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
            var httpClient = httpClientFactory.CreateClient("ReferenceApi");
            var response = await httpClient.GetFromJsonAsync<ReferenceResponse>("/api/reference");
            responseMessage = response?.Message ?? "The Reference API returned an empty response.";
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