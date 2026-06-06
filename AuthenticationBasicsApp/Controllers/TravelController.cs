
using AuthenticationBasicsApp.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationBasicsApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TravelController : ControllerBase
{
    private readonly Services.ICustomAuthorizationService _customAuthorizationService;
    private readonly HttpContext _httpContext;

    public TravelController(Services.ICustomAuthorizationService customAuthorizationService, IHttpContextAccessor httpContextAccessor)
    {
        _customAuthorizationService = customAuthorizationService;
        _httpContext = httpContextAccessor.HttpContext ?? throw new ArgumentNullException(nameof(httpContextAccessor));
    }
    
    [Authorize(AuthenticationSchemes = AuthenticationConstants.AuthenticationCookieSchema, Policy = "eu passport")]
    [HttpGet("sweden")]
    public IActionResult Sweden()
    {
        if(_httpContext.User.Identities.All(identity => identity.AuthenticationType != AuthenticationConstants.AuthenticationCookieSchema))
        {
            _httpContext.Response.StatusCode = 401;
            return Unauthorized();
        }
        
        if (_customAuthorizationService.CanGoToSweden())
        {
            return Ok("You are in Sweden");
        }
 
        _httpContext.Response.StatusCode = 403;
        return BadRequest("There is no access to sweden");
    }

    [Authorize(AuthenticationSchemes = AuthenticationConstants.AuthenticationCookieSchema, Policy = "eu passport")]
    [HttpGet("nor")]
    public IActionResult Norway()
    {
        if(_httpContext.User.Identities.All(identity => identity.AuthenticationType != AuthenticationConstants.AuthenticationCookieSchema))
        {
            _httpContext.Response.StatusCode = 401;
            return Unauthorized();
        }
        
        if (_customAuthorizationService.CanGoToNorway())
        {
            return Ok("You are in Norway");
        }
 
        _httpContext.Response.StatusCode = 403;
        return BadRequest("There is no access to Norway");
    }

    [Authorize(AuthenticationSchemes = AuthenticationConstants.AuthenticationCookieSchema2, Policy = "usa")]
    [HttpGet("usa")]
    public IActionResult Usa()
    {
        if(_httpContext.User.Identities.All(identity => identity.AuthenticationType != AuthenticationConstants.AuthenticationCookieSchema2))
        {
            _httpContext.Response.StatusCode = 401;
            return Unauthorized();
        }
        
        if (_customAuthorizationService.CanGoToUsa())
        {
            return Ok("You are in USA");
        }
 
        _httpContext.Response.StatusCode = 403;
        return BadRequest("There is no access to USA");
    }
    

}