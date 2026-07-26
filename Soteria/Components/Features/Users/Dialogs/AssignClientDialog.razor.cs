using Microsoft.AspNetCore.Components;
using MudBlazor;
using Soteria.Components.Features.Clients.Queries;
using Soteria.Components.Features.Shared;
using Soteria.Data.Authorization;

// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Features.Users.Dialogs;

public partial class AssignClientDialog
{
    [Inject]
    private UserService UserService { get; set; } = default!;
    [Inject]
    private IClientApplicationLookup ClientApplicationLookup { get; set; } = default!;
    [Inject]
    private IMudValidator<CreateClientMembershipRequest> CreateClientMembershipValidator { get; set; } = default!;

    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;
    [Parameter]
    public Guid UserId { get; set; }

    private MudForm Form { get; set; } = default!;
    private CreateClientMembershipRequest Request { get; } = new();
    private IReadOnlyList<ClientApplicationLookupItem> AvailableClients { get; set; } = [];
    private IReadOnlyList<MembershipLevel> MembershipLevels { get; } = Enum.GetValues<MembershipLevel>();
    private List<string> ErrorMessages { get; set; } = [];
    private bool IsLoading { get; set; }
    private bool IsSaving { get; set; }

    protected override async Task OnParametersSetAsync()
    {
        Request.UserId = UserId;
        Request.ClientId = string.Empty;
        Request.MembershipLevel = MembershipLevel.User;

        IsLoading = true;

        try
        {
            AvailableClients = await ClientApplicationLookup.GetAvailableClientsAsync(UserId);
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task SaveAsync()
    {
        ErrorMessages.Clear();

        await Form.ValidateAsync();

        if (!Form.IsValid)
        {
            return;
        }

        IsSaving = true;

        try
        {
            await UserService.CreateClientMembershipAsync(Request);
            MudDialog.Close(DialogResult.Ok(true));
        }
        catch (CreateClientMembershipValidationException exception)
        {
            ErrorMessages = exception.Failures
                .Select(failure => failure.ErrorMessage)
                .Distinct()
                .ToList();
        }
        catch (Exception)
        {
            ErrorMessages.Add(
                "The client membership could not be created. Review the selected values and try again.");
        }
        finally
        {
            IsSaving = false;
        }
    }

    private void Cancel()
    {
        MudDialog.Cancel();
    }
}