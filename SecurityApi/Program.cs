using SecurityApi.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Security API", Version = "v1",
        Description = "RESTful API for HTTP header analysis, IP reputation, and file hash lookups" });
});

// Register domain services
builder.Services.AddSingleton<IHeaderAnalysisService, HeaderAnalysisService>();
builder.Services.AddSingleton<IIpReputationService, IpReputationService>();
builder.Services.AddSingleton<IHashLookupService, HashLookupService>();
builder.Services.AddHttpClient();

var app = builder.Build();

// Configure pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
