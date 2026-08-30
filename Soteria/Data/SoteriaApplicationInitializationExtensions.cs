using Soteria.Data.Authorization;

namespace Soteria.Data;

internal static class SoteriaApplicationInitializationExtensions
{
    public static async Task InitialiseSoteriaAsync(this WebApplication app)
    {
        ArgumentNullException.ThrowIfNull(app);

        await using var scope = app.Services.CreateAsyncScope();

        if (app.Environment.IsDevelopment())
        {
            var openIddictInitializer = scope.ServiceProvider.GetRequiredService<OpenIddictInitializer>();
            await openIddictInitializer.InitializeAsync();
        }

        var soteriaAdminInitializer = scope.ServiceProvider.GetRequiredService<SoteriaAdministratorInitializer>();
        await soteriaAdminInitializer.InitializeAsync();
    }
}