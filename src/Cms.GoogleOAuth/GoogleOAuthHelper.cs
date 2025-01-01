using Cms.GoogleOAuth.Exceptions;
using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Oauth2.v2;
using Google.Apis.Oauth2.v2.Data;
using Google.Apis.Services;
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
    /// <param name="userId">The user identifier for storing the credentials.</param>
    /// <param name="cancellationToken">A cancellation token to cancel the operation.</param>
    /// <returns>A <see cref="UserCredential"/> object containing the access and refresh tokens.</returns>
    /// <exception cref="GoogleAuthException">Thrown when authentication fails.</exception>
    public async Task<UserCredential> AuthenticateAsync(string userId = "user",
        CancellationToken cancellationToken = default)
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
                userId,
                cancellationToken,
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
    /// <param name="userId">The user identifier for storing the credentials.</param>
    /// <param name="cancellationToken">A cancellation token to cancel the operation.</param>
    /// <returns>A <see cref="UserCredential"/> object containing the access and refresh tokens.</returns>
    /// <exception cref="ArgumentNullException">Thrown when additionalScopes is null.</exception>
    /// <exception cref="GoogleAuthException">Thrown when incremental authentication fails.</exception>
    public async Task<UserCredential> AuthenticateWithIncrementalScopesAsync(string[] additionalScopes,
        string userId = "user", CancellationToken cancellationToken = default)
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
                userId,
                cancellationToken,
                _dataStore
            );
        }
        catch (Exception ex)
        {
            throw new GoogleAuthException("Incremental authentication failed", ex);
        }
    }

    /// <summary>
    /// Exchanges an authorization code for a user credential.
    /// </summary>
    /// <param name="code">The authorization code received from the OAuth 2.0 authorization server.</param>
    /// <param name="redirectUri">The redirect URI used in the initial authorization request.</param>
    /// <param name="userId">The user identifier for storing the credentials.</param>
    /// <param name="cancellationToken">A cancellation token to cancel the operation.</param>
    /// <returns>A <see cref="UserCredential"/> object containing the access and refresh tokens.</returns>
    /// <exception cref="GoogleAuthException">Thrown when token exchange fails.</exception>
    public async Task<UserCredential> ExchangeCodeForTokenAsync(string code, string redirectUri, string userId = "user",
        CancellationToken cancellationToken = default)
    {
        var flow = CreateFlow();
        var token = await flow.ExchangeCodeForTokenAsync(userId, code, redirectUri, cancellationToken);

        return new UserCredential(flow, userId, token);
    }

    /// <summary>
    /// Gets the authorization URL for the OAuth 2.0 flow.
    /// </summary>
    /// <param name="redirectUri">The redirect URI to use after authorization.</param>
    /// <returns>The authorization URL.</returns>
    public string GetAuthorizationUrl(string redirectUri)
    {
        var flow = CreateFlow();
        var request = flow.CreateAuthorizationCodeRequest(redirectUri);

        return request.Build().ToString();
    }

    /// <summary>
    /// Refreshes the access token of a given <see cref="UserCredential"/>.
    /// </summary>
    /// <param name="credential">The <see cref="UserCredential"/> to refresh.</param>
    /// <param name="cancellationToken">A cancellation token to cancel the operation.</param>
    /// <returns>The refreshed <see cref="UserCredential"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when credential is null.</exception>
    /// <exception cref="GoogleAuthException">Thrown when token refresh fails.</exception>
    public static async Task<UserCredential> RefreshTokenAsync(UserCredential credential,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        try
        {
            await credential.RefreshTokenAsync(cancellationToken);
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
    /// <param name="cancellationToken">A cancellation token to cancel the operation.</param>
    /// <exception cref="ArgumentNullException">Thrown when credential is null.</exception>
    /// <exception cref="GoogleAuthException">Thrown when token revocation fails.</exception>
    public static async Task RevokeTokenAsync(UserCredential credential, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credential);

        try
        {
            await credential.RevokeTokenAsync(cancellationToken);
        }
        catch (TokenResponseException ex)
        {
            throw new GoogleAuthException("Token revocation failed", ex);
        }
    }

    /// <summary>
    /// Validates an ID token and returns its payload.
    /// </summary>
    /// <param name="idToken">The ID token to validate.</param>
    /// <returns>The payload of the validated ID token.</returns>
    /// <exception cref="GoogleAuthException">Thrown when ID token validation fails.</exception>
    public async Task<GoogleJsonWebSignature.Payload> ValidateIdTokenAsync(string idToken)
    {
        var validationSettings = new GoogleJsonWebSignature.ValidationSettings
        {
            Audience = [_clientId]
        };

        return await GoogleJsonWebSignature.ValidateAsync(idToken, validationSettings);
    }

    /// <summary>
    /// Validates an access token.
    /// </summary>
    /// <param name="accessToken">The access token to validate.</param>
    /// <returns>True if the access token is valid, false otherwise.</returns>
    public static async Task<bool> ValidateAccessTokenAsync(string accessToken)
    {
        var tokenInfoUrl = $"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={accessToken}";

        try
        {
            var httpClient = new HttpClient();
            var response = await httpClient.GetAsync(tokenInfoUrl);
            var isValid = response.IsSuccessStatusCode;

            return isValid;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Gets user information using the provided credential.
    /// </summary>
    /// <param name="credential">The user credential to use for the request.</param>
    /// <returns>User information from the Google OAuth2 v2 API.</returns>
    /// <exception cref="GoogleAuthException">Thrown when retrieving user information fails.</exception>
    public static async Task<Userinfo> GetUserInfoAsync(UserCredential credential)
    {
        try
        {
            var service = new Oauth2Service(new BaseClientService.Initializer
            {
                HttpClientInitializer = credential
            });

            var userInfo = await service.Userinfo.Get().ExecuteAsync();

            return userInfo;
        }
        catch (Exception ex)
        {
            throw new GoogleAuthException("Failed to retrieve user information", ex);
        }
    }

    /// <summary>
    /// Creates and initializes a new instance of GoogleAuthorizationCodeFlow.
    /// </summary>
    /// <returns>A new GoogleAuthorizationCodeFlow instance configured with the current client settings.</returns>
    private GoogleAuthorizationCodeFlow CreateFlow()
    {
        return new GoogleAuthorizationCodeFlow(new GoogleAuthorizationCodeFlow.Initializer
        {
            ClientSecrets = new ClientSecrets
            {
                ClientId = _clientId,
                ClientSecret = _clientSecret
            },
            Scopes = _scopes,
            DataStore = _dataStore
        });
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
