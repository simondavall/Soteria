var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var referenceApiBaseUrl = builder.Configuration["ReferenceApi:BaseUrl"]
                          ?? throw new InvalidOperationException(
                              "The ReferenceApi:BaseUrl configuration value is required.");

builder.Services.AddHttpClient("ReferenceApi", client =>
{
    client.BaseAddress = new Uri(referenceApiBaseUrl);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.MapGet("/api/reference", () =>
        Results.Ok(new
        {
            Message = "Reference API reachable"
        }))
    .WithName("GetReference");

app.Run();