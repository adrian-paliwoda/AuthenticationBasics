using AuthenticationBasicsApp.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using IAuthenticationService = AuthenticationBasicsApp.Services.IAuthenticationService;

namespace AuthenticationBasicsApp.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthenticationController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;

    public AuthenticationController(IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }

    [HttpGet("username")]
    [AllowAnonymous]
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
    [AllowAnonymous]
    public IActionResult Login()
    {
        return Login(new Credential
        {
            UserName = "adrian",
            Password ="test"
        });
    }

    [HttpGet("loginex")]
    [Authorize(Policy = "user")]
    public IActionResult LoginExternal()
    {
        return Challenge(
            new AuthenticationProperties { RedirectUri = "/api/travel/world" },
            AuthenticationConstants.AuthenticationOAuth);
    }
    
    [HttpPost("login")]
    [AllowAnonymous]
    public IActionResult Login([FromBody] Credential credential)
    {
        _authenticationService.SignIn(credential.UserName, credential.Password);
        return Ok();
    }

    [HttpGet("logout")]
    [AllowAnonymous]
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