using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationBasicsApp.Controllers;

[ApiController]
[AllowAnonymous]
[Route("api/auth")]
public class AuthenticationController : ControllerBase
{
    IDataProtectionProvider _dataProtectionProvider;
    
    public AuthenticationController(IDataProtectionProvider dataProtectionProvider)
    {
        _dataProtectionProvider = dataProtectionProvider;
    }
    
    [HttpGet("username")]
    public ActionResult UserName()
    {
        if (HttpContext.Request.Cookies.TryGetValue("auth", out var username))
        {
            var userNameUnprotect = _dataProtectionProvider.CreateProtector(nameof(AuthenticationController)).Unprotect(username);
            
            var usernameBytes = System.Convert.FromBase64String(userNameUnprotect);
            var usernameString = System.Text.Encoding.UTF8.GetString(usernameBytes);
            
            return Ok(usernameString.Split('=')[0]);
        }
        
        return NotFound("There is no such username");
    }
    
    [HttpGet("login")]
    public IActionResult Login()
    {
        var auth = "user:adrian";
        
        var authBytes = System.Text.Encoding.UTF8.GetBytes(auth);
        var authBase64 = System.Convert.ToBase64String(authBytes);
        
        var authProtected = _dataProtectionProvider.CreateProtector(nameof(AuthenticationController)).Protect(authBase64);
        
        HttpContext.Response.Cookies.Append("auth", authProtected);
        return Ok();
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        return Ok();
    }

    [HttpPost("register")]
    public IActionResult Register()
    {
        return Ok();
    }
}