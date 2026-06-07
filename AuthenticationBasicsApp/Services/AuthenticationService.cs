using System.Security.Claims;
using AuthenticationBasicsApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationBasicsApp.Services;

public class AuthenticationService : IAuthenticationService
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;

    public AuthenticationService(IHttpContextAccessor httpContextAccessor, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
    {
        _httpContextAccessor = httpContextAccessor;
        _userManager = userManager;
        _signInManager = signInManager;
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

    public async Task SignIn(string userName, string password)
    {
        var context = _httpContextAccessor.HttpContext;
        if (context == null)
        {
            return;
        }

        var user = await _userManager.FindByNameAsync(userName);
        if (user is null)
        {
            return;
        }

        var result = await _signInManager.PasswordSignInAsync(user.UserName!, password, false, false);
        if (!result.Succeeded)
        {
            return;
        }
        
        // the store is the source of truth: read roles + claims back from it
        var roles = await _userManager.GetRolesAsync(user);
        var storedClaims = await _userManager.GetClaimsAsync(user);
        

        var claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, user.UserName!),
        };
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));
        claims.AddRange(storedClaims.Where(c =>
            c.Type != ClaimTypes.Name && c.Type != ClaimTypes.Role));

        var claims2 = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, user.UserName!),
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