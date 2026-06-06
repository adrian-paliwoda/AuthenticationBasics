using System.Security.Claims;
using AuthenticationBasicsApp.Models;
using Microsoft.AspNetCore.Authentication;

namespace AuthenticationBasicsApp.Services;

public class AuthenticationService : IAuthenticationService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthenticationService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }
    
    public async Task SignIn()
    {
        var context = _httpContextAccessor.HttpContext;
        if (context == null)
        {
            return;
        }
        
        var userName = "adrian";
        
        var claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, userName),
            new Claim(ClaimTypes.Role, "admin"),
            new Claim(ClaimTypes.Role, "manager"),
            new Claim(ClaimTypes.Role, "user"),
            new Claim(AuthenticationConstants.Passport, "eu"),
            new Claim(AuthenticationConstants.Passport, "nor"),
        };
        
        var claims2 = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, userName),
            new Claim(AuthenticationConstants.Visa, "usa"),
        };
        var identity = new ClaimsIdentity(claims, AuthenticationConstants.AuthenticationCookieSchema);
        var identity2 = new ClaimsIdentity(claims2, AuthenticationConstants.AuthenticationCookieSchema2);

        var principal = new ClaimsPrincipal(identity);
        var principal2 = new ClaimsPrincipal(identity2);

        await context.SignInAsync(AuthenticationConstants.AuthenticationCookieSchema, principal);
        await context.SignInAsync(AuthenticationConstants.AuthenticationCookieSchema2, principal2);
    }

    public async Task SignOut()
    {
        var context = _httpContextAccessor.HttpContext;
        if (context == null)
        {
            return;
        }
        
        await context.SignOutAsync(AuthenticationConstants.AuthenticationCookieSchema);
        await context.SignOutAsync(AuthenticationConstants.AuthenticationCookieSchema2);
    }

    public string UserName()
    {
        var context = _httpContextAccessor.HttpContext;
        if (context == null)
        {
            return string.Empty;
        }

        var userName = context.User.FindFirst(ClaimTypes.Name)?.Value;
        

        return userName ?? string.Empty;
    }
}