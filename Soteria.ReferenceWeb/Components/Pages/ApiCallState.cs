namespace Soteria.ReferenceWeb.Components.Pages;

public sealed class ApiCallState
{
    public bool IsLoading { get; set; }

    public bool IsAccessDenied { get; set; }

    public string? SuccessMessage { get; set; }

    public string? ErrorMessage { get; set; }

    public void Begin()
    {
        IsLoading = true;
        IsAccessDenied = false;
        SuccessMessage = null;
        ErrorMessage = null;
    }

    public void Complete()
    {
        IsLoading = false;
    }
}