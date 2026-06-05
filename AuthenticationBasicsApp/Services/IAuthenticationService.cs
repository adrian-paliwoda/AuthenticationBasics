namespace AuthenticationBasicsApp.Services;

public interface IAuthenticationService
{
    Task SignIn();
    Task SignOut();
    string UserName();
}