namespace Politoria.Auth.Application.Services;

/// <summary>
/// Verifies HMAC-signed invite handoff tokens issued by HRMS.
/// HRMS owns the invite lifecycle (MembershipInvitation table); pishro-auth
/// trusts a valid handoff token as proof that the identityId came from a
/// successfully claimed invite and should be used as the User.Id for the
/// passkey registration about to happen.
/// </summary>
public interface IInviteHandoffService
{
    /// <summary>
    /// Parse and validate a handoff token.
    /// Returns null if signature is invalid or token has expired.
    /// </summary>
    InviteHandoff? Verify(string token);
}

public record InviteHandoff(Guid IdentityId, string DisplayName);
