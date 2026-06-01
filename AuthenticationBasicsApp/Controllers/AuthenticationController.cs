using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationBasicsApp.Controllers;

[ApiController]
[AllowAnonymous]
[Route("api/auth")]
public class AuthenticationController : ControllerBase
{
    [HttpGet("login")]
    public IActionResult Login()
    {
        HttpContext.Response.Headers.Append("set-cookie", "auth=user:adrian");
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