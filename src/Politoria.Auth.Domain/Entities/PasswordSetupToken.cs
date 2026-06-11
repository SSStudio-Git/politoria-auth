using System.ComponentModel.DataAnnotations;

namespace Politoria.Auth.Domain.Entities;

/// <summary>
/// req/004 — a single-use, URL-safe token for setting a password: both the
/// first-time "set your password" invite (admin-created accounts) and the
/// forgot-password reset. ~1h TTL.
/// </summary>
public class PasswordSetupToken : BaseEntity
{
    public Guid UserId { get; private set; }

    [MaxLength(128)]
    public string Token { get; private set; } = null!;

    public DateTimeOffset ExpiresAt { get; private set; }
    public bool IsUsed { get; private set; }

    private PasswordSetupToken() { }

    public static PasswordSetupToken Create(Guid userId, string token, TimeSpan ttl) => new()
    {
        UserId = userId,
        Token = token,
        ExpiresAt = DateTimeOffset.UtcNow.Add(ttl),
    };

    public bool IsLive => !IsUsed && DateTimeOffset.UtcNow < ExpiresAt;

    public void MarkUsed()
    {
        IsUsed = true;
        UpdatedAt = DateTimeOffset.UtcNow;
    }
}
