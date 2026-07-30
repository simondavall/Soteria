using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;
using Soteria.ReferenceWeb.Components.Reference;

namespace Soteria.ReferenceWeb.Components.Pages;

public partial class Auth(
    IJSRuntime jsRuntime,
    NavigationManager navigationManager)
    : IAsyncDisposable
{
    private readonly ApiCallState referenceApiState = new();
    private readonly ApiCallState editorApiState = new();
    private readonly ApiCallState auditorApiState = new();
    private readonly ApiCallState reviewApiState = new();

    private IJSObjectReference? module;

    private async Task CallReferenceApiAsync(
        ApiCallState state,
        string endpoint)
    {
        state.Begin();

        try
        {
            module ??=
                await jsRuntime.InvokeAsync<IJSObjectReference>(
                    "import",
                    "./js/reference-api.js");

            var result =
                await module.InvokeAsync<
                    ReferenceApiResult<ReferenceResponse>>(
                    "callReferenceApi",
                    endpoint);

            if (result.Status ==
                StatusCodes.Status401Unauthorized)
            {
                navigationManager.NavigateTo(
                    "/Account/Login?returnUrl=/auth",
                    forceLoad: true);

                return;
            }

            if (result.Status ==
                StatusCodes.Status403Forbidden)
            {
                state.IsAccessDenied = true;
                return;
            }

            if (!result.Ok)
            {
                state.ErrorMessage =
                    result.Message
                    ?? $"The Reference API request failed with " +
                    $"status {result.Status}.";

                return;
            }

            state.SuccessMessage =
                result.Data?.Message
                ?? result.Message
                ?? "The Reference API request succeeded.";
        }
        catch (JSException exception)
        {
            state.ErrorMessage =
                $"The Reference API request could not be completed: " +
                exception.Message;
        }
        finally
        {
            state.Complete();
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
}