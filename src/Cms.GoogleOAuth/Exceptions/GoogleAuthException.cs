namespace Cms.GoogleOAuth.Exceptions;

public class GoogleAuthException : Exception
{
    public GoogleAuthException(string message) : base(message) { }
    public GoogleAuthException(string message, Exception innerException) : base(message, innerException) { }
}
