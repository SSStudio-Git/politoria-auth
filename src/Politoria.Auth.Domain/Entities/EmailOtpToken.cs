using System.ComponentModel.DataAnnotations;

namespace Politoria.Auth.Domain.Entities;

/// <summary>
/// req/004 — a single-use email OTP for the mandatory second step of an
/// email+password login. 6-digit code, 5-min TTL, max 5 verify attempts.
/// </summary>
public class EmailOtpToken : BaseEntity
{
    public Guid UserId { get; private set; }

    [MaxLength(200)]
    public string Email { get; private set; } = null!;

    [MaxLength(12)]
    public string Code { get; private set; } = null!;

    public DateTimeOffset ExpiresAt { get; private set; }
    public int Attempts { get; private set; }
    public bool IsUsed { get; private set; }

    private EmailOtpToken() { }

    public static EmailOtpToken Create(Guid userId, string email, string code, TimeSpan ttl) => new()
    {
        UserId = userId,
        Email = email.ToLowerInvariant(),
        Code = code,
        ExpiresAt = DateTimeOffset.UtcNow.Add(ttl),
    };

    public bool IsLive => !IsUsed && DateTimeOffset.UtcNow < ExpiresAt && Attempts < 5;
    public bool Matches(string code) => IsLive && Code == code;

    public void RecordAttempt()
    {
        Attempts++;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void MarkUsed()
    {
        IsUsed = true;
        UpdatedAt = DateTimeOffset.UtcNow;
    }
}
