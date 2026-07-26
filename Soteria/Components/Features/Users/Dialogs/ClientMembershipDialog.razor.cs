using Microsoft.AspNetCore.Components;
using MudBlazor;
using Soteria.Components.Features.Clients.Queries;
using Soteria.Components.Features.Shared;
using Soteria.Data.Authorization;

// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Features.Users.Dialogs;

public partial class ClientMembershipDialog
{
    [Inject]
    private UserService UserService { get; set; } = default!;
    [Inject]
    private IClientApplicationLookup ClientApplicationLookup { get; set; } = default!;
    [Inject]
    private IMudValidator<CreateClientMembershipRequest> CreateClientMembershipValidator { get; set; } = default!;
    [Inject]
    private IMudValidator<EditClientMembershipRequest> EditClientMembershipValidator { get; set; } = default!;

    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;
    [Parameter]
    public Guid UserId { get; set; }
    [Parameter]
    public Guid? ClientMembershipId { get; set; }
    
    private MudForm Form { get; set; } = default!;
    private CreateClientMembershipRequest CreateRequest { get; } = new();
    private EditClientMembershipRequest? EditRequest { get; set; }
    private IReadOnlyList<ClientApplicationLookupItem> AvailableClients { get; set; } = [];
    private IReadOnlyList<ClientMembershipApplicationRoleItem> ApplicationRoles { get; set; } = [];
    private IReadOnlyList<MembershipLevel> MembershipLevels { get; } = Enum.GetValues<MembershipLevel>();
    private List<string> ErrorMessages { get; set; } = [];
    private bool IsLoading { get; set; }
    private bool IsSaving { get; set; }

    private bool IsEditMode => ClientMembershipId.HasValue;

    private bool SaveDisabled =>
        IsLoading
        || IsSaving
        || (!IsEditMode && AvailableClients.Count == 0)
        || (IsEditMode && EditRequest is null);
    
    protected override async Task OnParametersSetAsync()
    {
        ErrorMessages.Clear();
        IsLoading = true;

        try
        {
            if (IsEditMode)
            {
                EditRequest = await UserService.GetClientMembershipForEditAsync(UserId, ClientMembershipId!.Value);
                if (EditRequest is null)
                {
                    ApplicationRoles = [];
                    return;
                }

                ApplicationRoles = await UserService.GetClientMembershipApplicationRolesAsync(UserId, EditRequest.ClientMembershipId);

                EditRequest.AvailableApplicationRoleIds =
                    ApplicationRoles
                        .Select(role => role.ApplicationRoleId)
                        .ToList();
            }
            else
            {
                CreateRequest.UserId = UserId;
                CreateRequest.ClientId = string.Empty;
                CreateRequest.MembershipLevel = MembershipLevel.User;

                AvailableClients = await ClientApplicationLookup.GetAvailableClientsAsync(UserId);
            }
        }
        catch (Exception)
        {
            ErrorMessages.Add("The Client Membership information could not be loaded.");
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
            if (IsEditMode)
            {
                await UserService.UpdateClientMembershipAsync(EditRequest!);
            }
            else
            {
                await UserService.CreateClientMembershipAsync(CreateRequest);
            }

            MudDialog.Close(DialogResult.Ok(true));
        }
        catch (CreateClientMembershipValidationException exception)
        {
            SetValidationErrors(exception.Failures);
        }
        catch (EditClientMembershipValidationException exception)
        {
            SetValidationErrors(exception.Failures);
        }
        catch (ClientMembershipNotFoundException)
        {
            ErrorMessages.Add("The selected Client Membership could not be found.");
        }
        catch (Exception)
        {
            ErrorMessages.Add(
                IsEditMode
                    ? "The Client Membership could not be updated. Review the selected values and try again."
                    : "The Client Membership could not be created. Review the selected values and try again.");
        }
        finally
        {
            IsSaving = false;
        }
    }

    private bool IsRoleSelected(Guid applicationRoleId)
    {
        return EditRequest?.SelectedApplicationRoleIds.Contains(applicationRoleId) == true;
    }

    private void SetRoleSelected(Guid applicationRoleId, bool selected)
    {
        if (EditRequest is null)
        {
            return;
        }

        if (selected)
        {
            EditRequest.SelectedApplicationRoleIds.Add(applicationRoleId);
        }
        else
        {
            EditRequest.SelectedApplicationRoleIds.Remove(applicationRoleId);
        }
    }

    private void SetValidationErrors(IReadOnlyList<FluentValidation.Results.ValidationFailure> failures)
    {
        ErrorMessages = failures
            .Select(failure => failure.ErrorMessage)
            .Distinct()
            .ToList();
    }

    private void Cancel()
    {
        MudDialog.Cancel();
    }
}