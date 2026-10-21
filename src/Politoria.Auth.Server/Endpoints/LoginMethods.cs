namespace Politoria.Auth.Server.Endpoints;

/// <summary>
/// The way a browser session was opened, stamped on the login cookie (claim
/// <c>amr</c>) and reported on <see cref="Politoria.Contracts.Identity.UserSignedInEvent"/>.
/// </summary>
internal static class LoginMethods
{
    public const string ClaimType = "amr";
    public const string Passkey = "passkey";
    public const string Password = "password";
}
