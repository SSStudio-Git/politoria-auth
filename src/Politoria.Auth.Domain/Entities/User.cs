using System.ComponentModel.DataAnnotations;

namespace Politoria.Auth.Domain.Entities;

public class User : BaseEntity
{
    [MaxLength(50)]
    public string? DisplayName { get; private set; }

    [MaxLength(50)]
    public string? Nickname { get; private set; }

    [MaxLength(100)]
    public string? FirstName { get; private set; }

    [MaxLength(100)]
    public string? LastName { get; private set; }

    [MaxLength(200)]
    public string? Email { get; private set; }

    public bool EmailVerified { get; private set; }

    [MaxLength(20)]
    public string? Phone { get; private set; }

    public bool PhoneVerified { get; private set; }

    [MaxLength(500)]
    public string? AvatarUrl { get; private set; }

    [MaxLength(500)]
    public string? Bio { get; private set; }

    public bool IsActive { get; private set; } = true;

    // req/004 — optional email+password credential (BCrypt hash). Null for
    // passkey-only users; they cannot password-login.
    [MaxLength(200)]
    public string? PasswordHash { get; private set; }

    public DateTimeOffset? LastLoginAt { get; private set; }

    // req/004 C3 — brute-force lockout: count consecutive bad passwords; once the
    // threshold is hit, LockedUntil suspends password login for a cool-off window.
    public int FailedLoginCount { get; private set; }
    public DateTimeOffset? LockedUntil { get; private set; }

    public bool IsLockedOut => LockedUntil.HasValue && LockedUntil.Value > DateTimeOffset.UtcNow;

    public ICollection<PasskeyCredential> Passkeys { get; private set; } = new List<PasskeyCredential>();

    private User() { }

    public static User Create(string displayName)
    {
        return new User
        {
            DisplayName = displayName
        };
    }

    /// <summary>
    /// Create a User bound to a caller-supplied Id — used by the HRMS invite
    /// handoff so the pishro-auth User.Id equals the hrms_identity VerifiedIdentity
    /// id (the OIDC <c>sub</c>). Mirrors the passkey-invite path, which sets the same
    /// id on the User it creates at registration. The email is carried by the signed
    /// handoff so a password invitee can sign in by email afterwards.
    /// </summary>
    public static User CreateWithId(Guid id, string displayName, string? email = null)
    {
        return new User
        {
            Id = id,
            DisplayName = displayName,
            Email = email,
        };
    }

    public void Update(string? displayName = null, string? nickname = null, string? firstName = null,
        string? lastName = null, string? email = null, string? phone = null,
        string? avatarUrl = null, string? bio = null)
    {
        if (displayName is not null) DisplayName = displayName;
        if (nickname is not null) Nickname = nickname;
        if (firstName is not null) FirstName = firstName;
        if (lastName is not null) LastName = lastName;
        if (email is not null) Email = email;
        if (phone is not null) Phone = phone;
        if (avatarUrl is not null) AvatarUrl = avatarUrl;
        if (bio is not null) Bio = bio;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void SetEmailVerified(bool verified = true)
    {
        EmailVerified = verified;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void SetPhoneVerified(bool verified = true)
    {
        PhoneVerified = verified;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void RecordLogin()
    {
        LastLoginAt = DateTimeOffset.UtcNow;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    // req/004 C3 — record a failed password attempt; lock the account once the
    // threshold is reached (counter resets so the next window starts clean).
    public void RegisterFailedLogin(int threshold, TimeSpan lockDuration)
    {
        FailedLoginCount++;
        if (FailedLoginCount >= threshold)
        {
            LockedUntil = DateTimeOffset.UtcNow.Add(lockDuration);
            FailedLoginCount = 0;
        }
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    /// <summary>Clear the lockout counter — on a successful password verify or an admin unlock.</summary>
    public void ResetFailedLogins()
    {
        FailedLoginCount = 0;
        LockedUntil = null;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    // req/004 — set/replace the email+password credential (caller supplies the
    // BCrypt hash) and mark the email verified (set/reset happens via a token).
    public void SetPasswordHash(string passwordHash)
    {
        PasswordHash = passwordHash;
        EmailVerified = true;
        UpdatedAt = DateTimeOffset.UtcNow;
    }
}
