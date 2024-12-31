using Cms.GoogleOAuth.Exceptions;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Util.Store;

namespace Cms.GoogleOAuth;

/// <summary>
/// Provides methods to authenticate and manage OAuth 2.0 tokens for Google APIs.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="GoogleOAuthHelper"/> class.
/// </remarks>
/// <param name="clientId">The client ID obtained from the Google API Console.</param>
/// <param name="clientSecret">The client secret obtained from the Google API Console.</param>
/// <param name="scopes">An array of scopes to request access to.</param>
/// <param name="dataStore">The data store used to persist user credentials. If null, a default data store will be created.</param>
public class GoogleOAuthHelper(string clientId, string clientSecret, string[] scopes, IDataStore? dataStore = null)
{
    private readonly string _clientId = clientId ?? throw new ArgumentNullException(nameof(clientId));
    private readonly string _clientSecret = clientSecret ?? throw new ArgumentNullException(nameof(clientSecret));
    private readonly string[] _scopes = scopes ?? throw new ArgumentNullException(nameof(scopes));
    private readonly IDataStore _dataStore = dataStore ?? CreateDefaultDataStore();

    /// <summary>
    /// Authenticates the user and returns a <see cref="UserCredential"/> object.
    /// </summary>
    /// <returns>A <see cref="UserCredential"/> object containing the access and refresh tokens.</returns>
    /// <exception cref="GoogleAuthException">Thrown when authentication fails.</exception>
    public async Task<UserCredential> AuthenticateAsync()
    {
        try
        {
            var clientSecrets = new ClientSecrets
            {
                ClientId = _clientId,
                ClientSecret = _clientSecret
            };

            return await GoogleWebAuthorizationBroker.AuthorizeAsync(
                clientSecrets,
                _scopes,
                "user",
                CancellationToken.None,
                _dataStore
            );
        }
        catch (Exception ex)
        {
            throw new GoogleAuthException("Authentication failed", ex);
        }
    }

    /// <summary>
    /// Authenticates the user with additional scopes.
    /// </summary>
    /// <param name="additionalScopes">An array of additional scopes to request access to.</param>
    /// <returns>A <see cref="UserCredential"/> object containing the access and refresh tokens.</returns>
    /// <exception cref="ArgumentNullException">Thrown when additionalScopes is null.</exception>
    /// <exception cref="GoogleAuthException">Thrown when incremental authentication fails.</exception>
    public async Task<UserCredential> AuthenticateWithIncrementalScopesAsync(string[] additionalScopes)
    {
        ArgumentNullException.ThrowIfNull(additionalScopes);

        var allScopes = new List<string>(_scopes);
        allScopes.AddRange(additionalScopes);

        try
        {
            var clientSecrets = new ClientSecrets
            {
                ClientId = _clientId,
                ClientSecret = _clientSecret
            };

            return await GoogleWebAuthorizationBroker.AuthorizeAsync(
                clientSecrets,
                [.. allScopes],
                "user",
                CancellationToken.None,
                _dataStore
            );
        }
        catch (Exception ex)
        {
            throw new GoogleAuthException("Incremental authentication failed", ex);
        }
    }

    /// <summary>
    /// Refreshes the access token of a given <see cref="UserCredential"/>.
    /// </summary>
    /// <param name="credential">The <see cref="UserCredential"/> to refresh.</param>
    /// <returns>The refreshed <see cref="UserCredential"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when credential is null.</exception>
    /// <exception cref="GoogleAuthException">Thrown when token refresh fails.</exception>
    public static async Task<UserCredential> RefreshTokenAsync(UserCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);

        try
        {
            await credential.RefreshTokenAsync(CancellationToken.None);
            return credential;
        }
        catch (TokenResponseException ex)
        {
            throw new GoogleAuthException("Token refresh failed", ex);
        }
    }

    /// <summary>
    /// Revokes the access token of a given <see cref="UserCredential"/>.
    /// </summary>
    /// <param name="credential">The <see cref="UserCredential"/> to revoke.</param>
    /// <exception cref="ArgumentNullException">Thrown when credential is null.</exception>
    /// <exception cref="GoogleAuthException">Thrown when token revocation fails.</exception>
    public static async Task RevokeTokenAsync(UserCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);

        try
        {
            await credential.RevokeTokenAsync(CancellationToken.None);
        }
        catch (TokenResponseException ex)
        {
            throw new GoogleAuthException("Token revocation failed", ex);
        }
    }

    /// <summary>
    /// Creates a default data store for storing tokens.
    /// </summary>
    /// <returns>A default instance of <see cref="FileDataStore"/>.</returns>
    private static FileDataStore CreateDefaultDataStore()
    {
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var storageDirectory = Path.Combine(appDataPath, "GoogleOAuth", "Tokens");

        Directory.CreateDirectory(storageDirectory);

        return new FileDataStore(storageDirectory, true);
    }
}
