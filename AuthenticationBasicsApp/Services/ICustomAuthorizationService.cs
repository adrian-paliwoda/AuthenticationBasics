namespace AuthenticationBasicsApp.Services;

public interface ICustomAuthorizationService
{
    bool CanGoToSweden();
    bool CanGoToUsa();
    bool CanGoToNorway();
}