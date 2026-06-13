using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using AuthenticationBasicsApp.AuthenticationHandlers;
using AuthenticationBasicsApp.Models;
using AuthenticationBasicsApp.Services;
using AuthenticationBasicsApp.UserStore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
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
})
.AddSignInManager();

builder.Services.TryAddSingleton<IUserStore<IdentityUser>, InMemoryUserStore>();
// override the default UPPERCASE normalizer so roles/usernames keep their original casing
builder.Services.AddSingleton<ILookupNormalizer, NoOpLookupNormalizer>();

builder.Services
    .AddAuthentication(AuthenticationConstants.AuthenticationCookieSchema)
    .AddCookie(AuthenticationConstants.AuthenticationCookieSchema)
    .AddCookie(AuthenticationConstants.AuthenticationCookieSchema2)
    .AddCookie(AuthenticationConstants.AuthenticationCookieSchema3)
    .AddScheme<CookieAuthenticationOptions, VisitorAuthHandler>(AuthenticationConstants.AuthenticationCookieVisitor, options => { })
    .AddOAuth(AuthenticationConstants.AuthenticationOAuth, options =>
    {
        // Where the OAuth handler persists the authenticated principal after callback.
        // Schema3 is a registered cookie scheme, so this is correct.
        options.SignInScheme = AuthenticationConstants.AuthenticationCookieSchema3;

        // Credentials — pull from configuration/user-secrets instead of hardcoding.
        options.ClientId = builder.Configuration["OAuth:ClientId"] ?? "id";
        options.ClientSecret = builder.Configuration["OAuth:ClientSecret"] ?? "secret";

        // Hosted mock OAuth2 provider (kogiqa) using Google-style paths, which
        // return a JSON token response. Its /authorize redirects back to redirect_uri
        // with code + echoed state, so the auth-code flow completes against localhost.
        options.AuthorizationEndpoint = "https://oauth.kogiqa.com/o/oauth2/v2/auth";
        options.TokenEndpoint = "https://oauth.kogiqa.com/oauth2/v4/token";
        options.UserInformationEndpoint = "https://oauth.kogiqa.com/oauth2/v3/userinfo";

        // Must match the redirect URI the provider/mock sends the browser back to,
        // and must NOT collide with an MVC route. "/signin-oauth" is the conventional default.
        options.CallbackPath = "/signin-oauth";

        options.Scope.Add("profile");
        options.Scope.Add("email");

        options.SaveTokens = true;       // keep access/refresh tokens in auth properties
        options.UsePkce = true;          // PKCE — recommended for the auth-code flow

        // Map user-info JSON fields onto claims (runs during OnCreatingTicket).
        options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
        options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
        options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");

        // After the token is obtained, call the user-info endpoint and let the
        // ClaimActions above populate the identity from the returned JSON.
        options.Events = new OAuthEvents
        {
            OnCreatingTicket = async ctx =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                using var response = await ctx.Backchannel.SendAsync(
                    request, HttpCompletionOption.ResponseHeadersRead, ctx.HttpContext.RequestAborted);
                response.EnsureSuccessStatusCode();

                using var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                ctx.RunClaimActions(user.RootElement);
            }
        };
    });

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

    options.AddPolicy("customer", policy =>
    {
        policy.AddAuthenticationSchemes(AuthenticationConstants.AuthenticationCookieSchema,
                AuthenticationConstants.AuthenticationCookieVisitor)
            .RequireAuthenticatedUser();
    });
    
    options.AddPolicy("user", policy =>
    {
        policy.AddAuthenticationSchemes(AuthenticationConstants.AuthenticationCookieSchema)
            .RequireAuthenticatedUser();
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