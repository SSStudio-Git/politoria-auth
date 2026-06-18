namespace Politoria.Auth.Application.Services;

/// <summary>
/// req/004 — email + password authentication with a mandatory email-OTP second
/// step. Admins can invite (see <see cref="IssueSetupInviteAsync"/>); visitors can
/// also self-register (<see cref="RegisterAsync"/>) — both land on the same OTP
/// confirmation, and the portal's OIDC callback creates the PendingVetting member.
/// </summary>
public interface IPasswordAuthService
{
    /// <summary>Public self-signup: create an email+password account and send a
    /// confirmation OTP. Returns nothing (no enumeration) — if the email already
    /// exists, emails a "you already have an account" notice instead of creating one.</summary>
    Task RegisterAsync(string email, string password, string displayName, CancellationToken ct);

    /// <summary>Verify email+password; on success send an OTP. Returns true when an
    /// OTP was sent, false for any failure (generic — no enumeration).</summary>
    Task<bool> RequestLoginAsync(string email, string password, CancellationToken ct);

    /// <summary>Re-issue a sign-in OTP for an in-progress login/signup. Silent (no
    /// enumeration) and only fires if a flow was recently started for the email.</summary>
    Task ResendOtpAsync(string email, CancellationToken ct);

    /// <summary>Validate the OTP; on success record the login and return the user to
    /// sign in. Null on any failure.</summary>
    Task<SignedInUser?> VerifyOtpAsync(string email, string code, CancellationToken ct);

    /// <summary>Set/replace the password using a one-time setup/reset token.</summary>
    Task<bool> SetPasswordAsync(string token, string newPassword, CancellationToken ct);

    /// <summary>HRMS invite handoff: create-or-bind the User to the handoff's identity
    /// id, set its password (no OTP — the signed handoff is the proof of invite), and
    /// return the user to sign in. Mirrors the passkey-invite path. Null on a weak
    /// password.</summary>
    Task<SignedInUser?> SetPasswordFromInviteAsync(
        Guid identityId, string displayName, string? email, string newPassword, CancellationToken ct);

    /// <summary>Forgot-password: always succeeds; emails a reset link if the user exists.</summary>
    Task RequestResetAsync(string email, CancellationToken ct);

    /// <summary>Admin/invite: issue a "set your password" token + email for a user.</summary>
    Task IssueSetupInviteAsync(Guid userId, string email, CancellationToken ct);
}

public record SignedInUser(Guid UserId, string? DisplayName, string? Email, string? Phone);
