using System.Security.Claims;
using AuthenticationBasicsApp.Models;
using AuthenticationBasicsApp.Services;
using AuthenticationBasicsApp.UserStore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using AuthenticationService = AuthenticationBasicsApp.Services.AuthenticationService;
using IAuthenticationService = AuthenticationBasicsApp.Services.IAuthenticationService;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddIdentityCore<IdentityUser>(opt =>
{
    // relaxed rules so a simple test password like "test" is valid
    opt.Password.RequireNonAlphanumeric = false;
    opt.Password.RequireDigit = false;
    opt.Password.RequireUppercase = false;
    opt.Password.RequireLowercase = false;
    opt.Password.RequiredLength = 4;
});
builder.Services.TryAddSingleton<IUserStore<IdentityUser>, InMemoryUserStore>();
// override the default UPPERCASE normalizer so roles/usernames keep their original casing
builder.Services.AddSingleton<ILookupNormalizer, NoOpLookupNormalizer>();

builder.Services
    .AddAuthentication(AuthenticationConstants.AuthenticationCookieSchema)
    .AddCookie(AuthenticationConstants.AuthenticationCookieSchema)
    .AddCookie(AuthenticationConstants.AuthenticationCookieSchema2);

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("eu passport", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.AddAuthenticationSchemes(AuthenticationConstants.AuthenticationCookieSchema);
        policy.RequireClaim(AuthenticationConstants.Passport, "eu");
    });
    
    options.AddPolicy("usa", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.AddAuthenticationSchemes(AuthenticationConstants.AuthenticationCookieSchema2);
        policy.RequireClaim(AuthenticationConstants.Visa, "usa");
    });
});

builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
builder.Services.TryAddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.TryAddScoped<ICustomAuthorizationService, CustomAuthorizationService>();

builder.Services.AddControllers();


// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var userManager = scope.ServiceProvider.GetService<UserManager<IdentityUser>>();

    if (userManager != null)
    {
        var userName = "adrian";
        var email = "adrian@test.com";
        var password = "test";
    
        if (await userManager.FindByNameAsync(userName) is null)
        {
            var user = new IdentityUser()
            {
                UserName = userName,
                Email = userName,
                EmailConfirmed = true,
                PhoneNumberConfirmed = true,
            };
            
            var result = await userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                throw new Exception("Seeding user failed: " +
                    string.Join("; ", result.Errors.Select(e => e.Description)));
            }
            
            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, userName),
                new Claim(ClaimTypes.Role, "admin"),
                new Claim(ClaimTypes.Role, "manager"),
                new Claim(ClaimTypes.Role, "user"),
                new Claim(AuthenticationConstants.Passport, "eu"),
                new Claim(AuthenticationConstants.Passport, "nor"),
            };
            
            await userManager.AddToRolesAsync(user, new[] { "user", "admin", "manager" });
            await userManager.AddClaimsAsync(user, claims);
        }
    }
}

// Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.MapOpenApi();
    }


app.UseHttpsRedirection();
app.UseCors(policy => policy.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin());

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();