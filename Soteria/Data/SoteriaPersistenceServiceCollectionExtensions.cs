using Microsoft.EntityFrameworkCore;

namespace Soteria.Data;

internal static class SoteriaPersistenceServiceCollectionExtensions
{
    public static IServiceCollection AddSoteriaPersistence(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var connectionString = configuration.GetConnectionString("SoteriaDb")
                               ?? throw new InvalidOperationException(
                                   "Connection string 'SoteriaDb' not found.");

        services.AddDbContext<SoteriaDbContext>(options => options.UseSqlite(connectionString));

        services.AddDatabaseDeveloperPageExceptionFilter();

        return services;
    }
}