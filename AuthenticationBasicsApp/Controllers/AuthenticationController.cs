using AuthenticationBasicsApp.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationBasicsApp.Controllers;

[ApiController]
[AllowAnonymous]
[Route("api/auth")]
public class AuthenticationController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    IDataProtectionProvider _dataProtectionProvider;

    public AuthenticationController(IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }

    [HttpGet("username")]
    public ActionResult UserName()
    {
        var userName = _authenticationService.UserName();

        if (string.IsNullOrEmpty(userName))
        {
            return NotFound("There is no such username");
        }

        return Ok(userName);
    }

    [HttpGet("login")]
    public IActionResult Login()
    {
        _authenticationService.SignIn();
        return Ok();
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        _authenticationService.SignOut();
        return Ok();
    }

    [HttpPost("register")]
    public IActionResult Register()
    {
        return Ok();
    }
}