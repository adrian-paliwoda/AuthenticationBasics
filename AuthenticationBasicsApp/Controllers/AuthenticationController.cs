using System.Security.Claims;
using AuthenticationBasicsApp.Models;
using AuthenticationBasicsApp.UserStore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using IAuthenticationService = AuthenticationBasicsApp.Services.IAuthenticationService;

namespace AuthenticationBasicsApp.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthenticationController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    private readonly IPasswordHasher<User> _passwordHasher;
    private readonly IDataProtectionProvider _dataProtectionProvider;
    private readonly Database _database;

    public AuthenticationController(
        IAuthenticationService authenticationService,
        IPasswordHasher<User> passwordHasher,
        IDataProtectionProvider dataProtectionProvider,
        Database database)
    {
        _authenticationService = authenticationService;
        _passwordHasher = passwordHasher;
        _dataProtectionProvider = dataProtectionProvider;
        _database = database;
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
    public Task<IActionResult> Login(CancellationToken cancellationToken)
    {
        return Login(new Credential
        {
            UserName = "adrian",
            Password = "test"
        }, cancellationToken);
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
    public async Task<IActionResult> Login([FromBody] Credential credential, CancellationToken cancellationToken)
    {
        var user = await _database.GetUserAsync(credential.UserName, cancellationToken: cancellationToken);
        if (user == null)
        {
            return NotFound("There is no such username");
        }

        var result = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, credential.Password);
        if (result == PasswordVerificationResult.Failed)
        {
            return Unauthorized();
        }

        await HttpContext.SignInAsync(AuthenticationConstants.AuthenticationCookieSchema,
            UserHelper.ConvertToClaimsPrincipal(user));
        return Ok();
    }

    [HttpGet("promote")]
    [AllowAnonymous]
    public async Task<IActionResult> Promote(string username, CancellationToken cancellationToken)
    {
        var user = await _database.GetUserAsync(username, cancellationToken: cancellationToken);
        if (user == null)
        {
            return NotFound("There is no such username");
        }

        user.Claims.Add(new UserClaim() { Type = ClaimTypes.Country, Value = "Poland" });
        user.Claims.Add(new UserClaim() { Type = AuthenticationConstants.Passport, Value = "eu" });
        user.Claims.Add(new UserClaim() { Type = AuthenticationConstants.Passport, Value = "nor" });

        await _database.PutAsync(user, cancellationToken);

        return Ok();
    }

    [HttpGet("start-password-reset")]
    public async Task<string> PasswordReset([FromQuery] string username, CancellationToken cancellationToken)
    {
        var protector = _dataProtectionProvider.CreateProtector("password-reset");
        var user = await _database.GetUserAsync(username, cancellationToken);
        if (user == null)
        {
            return string.Empty;
        }

        return protector.Protect(user.Username);
    }

    [HttpGet("end-password-reset")]
    public async Task<string> EndPasswordReset(
        [FromQuery] string username, 
        [FromQuery] string password,
        [FromQuery] string hash, 
        CancellationToken cancellationToken)
    {
        var protector = _dataProtectionProvider.CreateProtector("password-reset");
        var unprotectedHash = protector.Unprotect(hash);

        if (unprotectedHash != password)
        {
            return string.Empty;
        }

        var user = await _database.GetUserAsync(username, cancellationToken);
        if (user == null)
        {
            return string.Empty;
        }

        user.PasswordHash = _passwordHasher.HashPassword(user, password);

        return "Password reset";
    }

    [HttpGet("logout")]
    [AllowAnonymous]
    public IActionResult Logout()
    {
        _authenticationService.SignOut();
        return Ok();
    }
}