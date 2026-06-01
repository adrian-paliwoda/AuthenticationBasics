using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationBasicsApp.Controllers;

[ApiController]
[AllowAnonymous]
[Route("api/auth")]
public class AuthenticationController : ControllerBase
{
    [HttpGet("username")]
    public ActionResult UserName()
    {
        if (HttpContext.Request.Cookies.TryGetValue("username", out var username))
        {
            return Ok(username);
        }
        
        return NotFound("There is no such username");
    }
    
    [HttpGet("login")]
    public IActionResult Login()
    {
        HttpContext.Response.Cookies.Append("auth", "user:adrian");
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