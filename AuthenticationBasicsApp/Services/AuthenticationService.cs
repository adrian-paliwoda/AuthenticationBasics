using System.Security.Claims;
using AuthenticationBasicsApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace AuthenticationBasicsApp.Services;

public class AuthenticationService : IAuthenticationService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthenticationService(IDataProtectionProvider dataProtectionProvider, IHttpContextAccessor httpContextAccessor)
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
        
        var claim = new Claim(ClaimTypes.Name, userName);
        var claims = new List<Claim>()
        {
            claim
        };
        var identity = new ClaimsIdentity(claims, AuthenticationConstants.AuthenticationCookieSchema);
        identity.AddClaim(claim);

        var principal = new ClaimsPrincipal(identity);

        await context.SignInAsync(AuthenticationConstants.AuthenticationCookieSchema, principal);
    }

    public async Task SignOut()
    {
        var context = _httpContextAccessor.HttpContext;
        if (context == null)
        {
            return;
        }
        
        await context.SignOutAsync(AuthenticationConstants.AuthenticationCookieSchema);
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