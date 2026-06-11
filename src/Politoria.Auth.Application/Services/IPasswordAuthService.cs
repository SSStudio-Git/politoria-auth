namespace Politoria.Auth.Application.Services;

/// <summary>
/// req/004 — email + password authentication with a mandatory email-OTP second
/// step. Account creation stays invite/admin-only (see <see cref="IssueSetupInviteAsync"/>).
/// </summary>
public interface IPasswordAuthService
{
    /// <summary>Verify email+password; on success send an OTP. Returns true when an
    /// OTP was sent, false for any failure (generic — no enumeration).</summary>
    Task<bool> RequestLoginAsync(string email, string password, CancellationToken ct);

    /// <summary>Validate the OTP; on success record the login and return the user to
    /// sign in. Null on any failure.</summary>
    Task<SignedInUser?> VerifyOtpAsync(string email, string code, CancellationToken ct);

    /// <summary>Set/replace the password using a one-time setup/reset token.</summary>
    Task<bool> SetPasswordAsync(string token, string newPassword, CancellationToken ct);

    /// <summary>Forgot-password: always succeeds; emails a reset link if the user exists.</summary>
    Task RequestResetAsync(string email, CancellationToken ct);

    /// <summary>Admin/invite: issue a "set your password" token + email for a user.</summary>
    Task IssueSetupInviteAsync(Guid userId, string email, CancellationToken ct);
}

public record SignedInUser(Guid UserId, string? DisplayName, string? Email, string? Phone);
