using System.Security.Claims;
using AuthenticationBasicsApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace AuthenticationBasicsApp.Middlewares;

public class AuthenticationMiddleware
{
    private readonly RequestDelegate _next;

    public AuthenticationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var dataProtectionProvider = context.RequestServices.GetService<IDataProtectionProvider>();
        if (dataProtectionProvider == null)
        {
            await _next(context);
            return;
        }

        if (context.Request.Cookies.TryGetValue("auth", out var username))
        {
            var userNameUnprotect = dataProtectionProvider
                .CreateProtector(AuthenticationConstants.AuthenticationCookieDataProtectionName)
                .Unprotect(username);

            var userNameBytes = Convert.FromBase64String(userNameUnprotect);
            var userNameString = System.Text.Encoding.UTF8.GetString(userNameBytes);

            userNameString = userNameString.Split('=')[0];

            var claim = new Claim(ClaimTypes.Name, userNameString);
            var claims = new List<Claim>()
            {
                claim
            };
            var identity = new ClaimsIdentity(claims, AuthenticationConstants.AuthenticationCookieSchema);
            identity.AddClaim(claim);

            var principal = new ClaimsPrincipal(identity);

            context.User = principal;
        }


        await _next(context);
    }
}

public static class AuthenticationMiddlewareExtensions
{
    public static IApplicationBuilder UseAuthenticationMiddleware(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<AuthenticationMiddleware>();
    }
}