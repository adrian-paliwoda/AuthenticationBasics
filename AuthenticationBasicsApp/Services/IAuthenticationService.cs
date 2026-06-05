namespace AuthenticationBasicsApp.Services;

public interface IAuthenticationService
{
    void SignIn();
    void SignOut();
    string UserName();
}