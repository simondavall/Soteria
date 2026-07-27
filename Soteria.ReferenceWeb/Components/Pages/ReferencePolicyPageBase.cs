using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;
using Soteria.ReferenceWeb.Components.Reference;

namespace Soteria.ReferenceWeb.Components.Pages;

public abstract class ReferencePolicyPageBase : ComponentBase, IAsyncDisposable
{
    private IJSObjectReference? module;

    [Inject]
    private IJSRuntime JsRuntime { get; set; } = null!;
    [Inject]
    private NavigationManager NavigationManager { get; set; } = null!;

    protected bool IsLoading { get; private set; }
    protected string? ResponseMessage { get; private set; }
    protected string? ErrorMessage { get; private set; }
    protected abstract string ApiEndpoint { get; }
    protected abstract string ReturnUrl { get; }

    protected async Task CallReferenceApiAsync()
    {
        IsLoading = true;
        ResponseMessage = null;
        ErrorMessage = null;

        try
        {
            module ??= await JsRuntime.InvokeAsync<IJSObjectReference>("import", "./js/reference-api.js");

            var result = await module.InvokeAsync<ReferenceApiResult<ReferenceResponse>>("callReferenceApi", ApiEndpoint);
            if (result.Status == StatusCodes.Status401Unauthorized)
            {
                NavigationManager.NavigateTo($"/Account/Login?returnUrl={Uri.EscapeDataString(ReturnUrl)}", forceLoad: true);
                return;
            }

            if (!result.Ok)
            {
                ErrorMessage = result.Message ?? $"The Reference API request failed with " + $"status {result.Status}.";
                return;
            }

            ResponseMessage = result.Data?.Message ?? result.Message ?? "The Reference API returned an empty response.";
        }
        catch (JSException exception)
        {
            ErrorMessage = $"The Reference API request could not be completed: {exception.Message}";
        }
        finally
        {
            IsLoading = false;
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