namespace Politoria.Auth.Application.Services;

/// <summary>
/// HRMS mints a NEW identity id on every invite claim, so an invite can carry an
/// email that already belongs to an existing auth account under a different id.
/// Neither invite path (password or passkey) may touch or duplicate that account:
/// both refuse with this error code and the invite pages send the person to the
/// normal sign-in instead.
/// </summary>
public static class InviteAccountGuard
{
    public const string ExistingAccountError = "existing_account";
    public const string ExistingAccountMessage = "You already have an account with this email. Sign in instead.";

    public static string? Normalize(string? email) =>
        string.IsNullOrWhiteSpace(email) ? null : email.Trim().ToLowerInvariant();
}
