using System.Security.Claims;
using AuthenticationBasicsApp.Models;
using Microsoft.AspNetCore.DataProtection;

namespace AuthenticationBasicsApp.Services;

public class AuthenticationService : IAuthenticationService
{
    private readonly IDataProtectionProvider _dataProtectionProvider;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthenticationService(IDataProtectionProvider dataProtectionProvider, IHttpContextAccessor httpContextAccessor)
    {
        _dataProtectionProvider = dataProtectionProvider;
        _httpContextAccessor = httpContextAccessor;
    }
    
    public void SignIn()
    {
        var auth = "user:adrian";
        
        var authBytes = System.Text.Encoding.UTF8.GetBytes(auth);
        var authBase64 = Convert.ToBase64String(authBytes);
        
        var authProtected = _dataProtectionProvider
            .CreateProtector(AuthenticationConstants.AuthenticationCookieDataProtectionName)
            .Protect(authBase64);
        
        _httpContextAccessor.HttpContext?.Response.Cookies.Append("auth", authProtected);
    }

    public void SignOut()
    {
        var auth = "user:adrian";
        _httpContextAccessor.HttpContext?.Response.Cookies.Delete(auth);
    }

    public string UserName()
    {
        var userName = _httpContextAccessor.HttpContext?.User.Identities.FirstOrDefault()?.FindFirst(ClaimTypes.Name)?.Value;

        return userName ?? string.Empty;
    }
}