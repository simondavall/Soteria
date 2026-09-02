using Serilog;

namespace Soteria.Infrastructure.Logging;

internal static class SoteriaLoggingExtensions
{
    public static void AddSoteriaLogging(this WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var logFilePath = builder.Configuration["Serilog:WriteTo:Sink:Args:path"];

        if (string.IsNullOrWhiteSpace(logFilePath))
        {
            throw new InvalidOperationException("Logging configuration 'Serilog:WriteTo:Sink:Args:path' is required.");
        }
        
        Log.Logger = new LoggerConfiguration()
            .ReadFrom.Configuration(builder.Configuration)
            .CreateBootstrapLogger();
        
        builder.Logging.ClearProviders();

        builder.Services.AddSerilog((services, configuration) =>
        {
            configuration
                .ReadFrom.Configuration(builder.Configuration)
                .ReadFrom.Services(services)
                .Enrich.FromLogContext();
        });
    }
}