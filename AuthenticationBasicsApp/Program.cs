using AuthenticationBasicsApp.Middlewares;
using Microsoft.Extensions.DependencyInjection.Extensions;
using AuthenticationService = AuthenticationBasicsApp.Services.AuthenticationService;
using IAuthenticationService = AuthenticationBasicsApp.Services.IAuthenticationService;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
builder.Services.TryAddScoped<IAuthenticationService, AuthenticationService>();

builder.Services.AddControllers();


// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors(policy => policy.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin());

app.UseAuthenticationMiddleware();

app.UseAuthorization();

app.MapControllers();

app.Run();