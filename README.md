# Cms.GoogleOAuth
## Overview
#### `Cms.GoogleOAuth` is a C# library that simplifies the process of authenticating and managing OAuth 2.0 tokens for Google APIs. It provides a set of methods to handle various aspects of Google OAuth 2.0 authentication flow.

## Features
🔐 User authentication with Google OAuth 2.0

🔄 Token management (refresh, revoke)

🕵️ ID token and access token validation

👤 User information retrieval

📦 Supports multiple application types (Web, API, Console)

## Installation
#### To install `Cms.GoogleOAuth`, run the following command in .NET CLI:
```bash
dotnet add package Cms.GoogleOAuth
```
## Usage
#### Here's a basic example of how to use Cms.GoogleOAuth:

## API Reference
- `AuthenticateAsync`: Authenticates the user and returns a UserCredential object.
- `AuthenticateWithIncrementalScopesAsync`: Authenticates the user with additional scopes.
- `ExchangeCodeForTokenAsync`: Exchanges an authorization code for a user credential.
- `GetAuthorizationUrl`: Gets the authorization URL for the OAuth 2.0 flow.
- `RefreshTokenAsync`: Refreshes the access token of a given UserCredential.
- `RevokeTokenAsync`: Revokes the access token of a given UserCredential.
- `ValidateIdTokenAsync`: Validates an ID token and returns its payload.
- `ValidateAccessTokenAsync`: Validates an access token.
- `GetUserInfoAsync`: Gets user information using the provided credential.

## Considerations
- **Security**: Make sure you store your credentials and tokens securely.
- **Scopes**: Define appropriate scopes based on the information you need to access.
- **Error Handling**: Implement appropriate error handling during authentication and token operations.

## Contributing
#### Contributions are welcome! Please feel free to submit a Pull Request.

## License
#### This project is licensed under the MIT License.
