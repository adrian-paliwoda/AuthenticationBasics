using AuthenticationBasicsApp.Startup;
using AuthenticationBasicsApp.UserStore;

var builder = WebApplication.CreateBuilder(args);

builder.AddAuthSetup();
builder.Services.AddControllers();


builder.Services.AddOpenApi();

var app = builder.Build();
await UserManagerHelper.SetupUsersAsync(app);

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors(policy => policy
    .AllowAnyHeader()
    .AllowAnyMethod()
    .AllowAnyOrigin());

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();