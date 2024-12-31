using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Util.Store;

namespace Cms.GoogleOAuth;

public class GoogleOAuthHelper
{
    private readonly GoogleAuthorizationCodeFlow _flow;
    private readonly string _redirectUri;

    /// <summary>
    /// Initializes a new instance of the GoogleOAuthHelper class.
    /// </summary>
    /// <param name="clientId">The client ID obtained from the Google API Console.</param>
    /// <param name="clientSecret">The client secret obtained from the Google API Console.</param>
    /// <param name="redirectUri">The redirect URI for the OAuth 2.0 flow.</param>
    /// <param name="scopes">An array of scopes to request access to.</param>
    /// <param name="dataStore">The data store used to persist user credentials.</param>
    public GoogleOAuthHelper(string clientId, string clientSecret, string redirectUri, string[] scopes,
        IDataStore? dataStore = null)
    {
        _redirectUri = redirectUri;
        _flow = new GoogleAuthorizationCodeFlow(new GoogleAuthorizationCodeFlow.Initializer
        {
            ClientSecrets = new ClientSecrets
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            },
            Scopes = scopes,
            DataStore = dataStore ?? CreateDefaultDataStore()
        });
    }

    /// <summary>
    /// Gets the authorization URL for the OAuth 2.0 flow.
    /// </summary>
    /// <returns>The authorization URL.</returns>
    public string GetAuthorizationUrl() => _flow.CreateAuthorizationCodeRequest(_redirectUri).Build().ToString();

    /// <summary>
    /// Exchanges an authorization code for user credentials.
    /// </summary>
    /// <param name="code">The authorization code received from the OAuth 2.0 flow.</param>
    /// <returns>A UserCredential object.</returns>
    public async Task<UserCredential> ExchangeCodeForTokenAsync(string code)
    {
        var token = await _flow.ExchangeCodeForTokenAsync("user", code, _redirectUri, CancellationToken.None);
        return new UserCredential(_flow, "user", token);
    }

    /// <summary>
    /// Refreshes the access token of a UserCredential.
    /// </summary>
    /// <param name="credential">The UserCredential to refresh.</param>
    /// <returns>The refreshed UserCredential.</returns>
    public static async Task<UserCredential> RefreshTokenAsync(UserCredential credential)
    {
        await credential.RefreshTokenAsync(CancellationToken.None);
        return credential;
    }

    private static FileDataStore CreateDefaultDataStore()
    {
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var storageDirectory = Path.Combine(appDataPath, "GoogleOAuth", "Tokens");

        // Ensure the directory exists
        Directory.CreateDirectory(storageDirectory);

        return new FileDataStore(storageDirectory, true);
    }
}
