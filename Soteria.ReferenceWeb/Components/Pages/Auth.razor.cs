using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace Soteria.ReferenceWeb.Components.Pages;

public partial class Auth(IJSRuntime jsRuntime, NavigationManager navigationManager) : IAsyncDisposable
{
    private IJSObjectReference? module;
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
            module ??= await jsRuntime.InvokeAsync<IJSObjectReference>(
                "import",
                "./js/reference-api.js");

            var result =
                await module.InvokeAsync<ReferenceApiResult>(
                    "callReferenceApi");

            if (result.Status == StatusCodes.Status401Unauthorized)
            {
                navigationManager.NavigateTo(
                    "/Account/Login?returnUrl=/auth",
                    forceLoad: true);

                return;
            }

            if (!result.Ok)
            {
                errorMessage =
                    result.Message ??
                    $"The Reference API request failed with status " +
                    $"{result.Status}.";

                return;
            }

            responseMessage =
                result.Message ??
                "The Reference API returned an empty response.";
        }
        catch (JSException exception)
        {
            errorMessage =
                $"The Reference API request could not be completed: " +
                exception.Message;
        }
        finally
        {
            isLoading = false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (module is not null)
        {
            try
            {
                await module.DisposeAsync();
            }
            catch (JSDisconnectedException)
            {
                // The browser circuit has already disconnected.
            }
        }
    }

    private sealed record ReferenceApiResult(
        bool Ok,
        int Status,
        string? Message);
}