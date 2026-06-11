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

    public ICollection<PasskeyCredential> Passkeys { get; private set; } = new List<PasskeyCredential>();

    private User() { }

    public static User Create(string displayName)
    {
        return new User
        {
            DisplayName = displayName
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

    // req/004 — set/replace the email+password credential (caller supplies the
    // BCrypt hash) and mark the email verified (set/reset happens via a token).
    public void SetPasswordHash(string passwordHash)
    {
        PasswordHash = passwordHash;
        EmailVerified = true;
        UpdatedAt = DateTimeOffset.UtcNow;
    }
}
