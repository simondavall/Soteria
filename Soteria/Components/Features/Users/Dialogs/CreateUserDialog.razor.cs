using Microsoft.AspNetCore.Components;
using MudBlazor;
using Soteria.Components.Features.Shared;

// ReSharper disable NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract

namespace Soteria.Components.Features.Users.Dialogs;

public partial class CreateUserDialog
{
    [Inject]
    private UserService UserService { get; set; } = default!;
    [Inject]
    private IMudValidator<CreateUserRequest> CreateUserValidator { get; set; } = default!;

    [CascadingParameter]
    private IMudDialogInstance MudDialog { get; set; } = default!;

    private MudForm Form { get; set; } = default!;
    private CreateUserRequest Request { get; } = new();
    private List<string> ErrorMessages { get; set; } = [];
    private bool IsSaving { get; set; }

    private async Task RegisterAsync()
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
            var result = await UserService.CreateUserAsync(Request);
            MudDialog.Close(DialogResult.Ok(result.UserId));
        }
        catch (CreateUserValidationException exception)
        {
            ErrorMessages =
                exception.Failures
                    .Select(error => error.ErrorMessage)
                    .ToList();
        }
        catch (CreateUserIdentityException exception)
        {
            ErrorMessages =
                exception.Errors
                    .Select(error => error.Description)
                    .ToList();
        }
        catch (Exception)
        {
            ErrorMessages.Add(
                "The user could not be registered. " +
                "Review the entered values and try again.");
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