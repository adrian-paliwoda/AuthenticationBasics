using AuthenticationBasicsApp.AuthenticationHandlers;
using AuthenticationBasicsApp.Models;
using AuthenticationBasicsApp.Polices;
using AuthenticationBasicsApp.Services;
using AuthenticationBasicsApp.UserStore;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using AuthenticationService = AuthenticationBasicsApp.Services.AuthenticationService;
using IAuthenticationService = AuthenticationBasicsApp.Services.IAuthenticationService;

namespace AuthenticationBasicsApp.Startup;

public static class AuthStartup
{
    public static WebApplicationBuilder AddAuthSetup(this WebApplicationBuilder builder)
    {
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

        builder.Services.TryAddSingleton<IPasswordHasher<User>, PasswordHasher<User>>();
        builder.Services.TryAddSingleton<Database>();

        builder.Services.TryAddSingleton<IUserStore<IdentityUser>, InMemoryUserStore>();
        builder.Services.AddSingleton<ILookupNormalizer, NoOpLookupNormalizer>();

        builder.Services
            .AddAuthentication(AuthenticationConstants.AuthenticationCookieSchema)
            .AddCookie(AuthenticationConstants.AuthenticationCookieSchema)
            .AddCookie(AuthenticationConstants.AuthenticationCookieSchema2)
            .AddCookie(AuthenticationConstants.AuthenticationCookieSchema3)
            .AddScheme<CookieAuthenticationOptions, VisitorAuthHandler>(
                AuthenticationConstants.AuthenticationCookieVisitor, _ => { })
            .AddOAuthSetup(builder.Configuration);

        builder.Services.AddAuthenticationPolicies();

        builder.Services.AddDataProtection();
        builder.Services.AddHttpContextAccessor();
        builder.Services.TryAddScoped<IAuthenticationService, AuthenticationService>();
        builder.Services.TryAddScoped<ICustomAuthorizationService, CustomAuthorizationService>();

        return builder;
    }
}