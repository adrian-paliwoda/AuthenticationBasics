using AuthenticationBasicsApp.Models;
using AuthenticationBasicsApp.UserStore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationBasicsApp.Controllers;

[ApiController]
[Route("api/[controller]")]
[AllowAnonymous]
public class RegistrationController : ControllerBase
{
    private readonly IPasswordHasher<User> _passwordHasher;
    private readonly Database _database;

    public RegistrationController(IPasswordHasher<User> passwordHasher, Database database)
    {
        _passwordHasher = passwordHasher;
        _database = database;
    }
    
    [HttpPost]
    public async Task<IActionResult> Register([FromBody] Credential credential, CancellationToken cancellationToken)
    {
        var user = new User()
        {
            Username =  credential.UserName,
        };
        user.PasswordHash = _passwordHasher.HashPassword(user, credential.Password);
        await _database.PutAsync(user, cancellationToken);

        await HttpContext.SignInAsync(AuthenticationConstants.AuthenticationCookieSchema, UserHelper.ConvertToClaimsPrincipal(user));
        
        return Ok();
    }
    
    [HttpGet]
    public Task<IActionResult> Reg(CancellationToken cancellationToken)
    {
        var credential = new Credential()
        {
            UserName = "adrian",
            Password = "test"
        };
        
        return Register(credential, cancellationToken);
    }
}