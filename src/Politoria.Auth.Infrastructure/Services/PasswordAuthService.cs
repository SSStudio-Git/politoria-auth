using System.Security.Cryptography;
using MassTransit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Politoria.Auth.Application.Services;
using Politoria.Auth.Domain.Entities;
using Politoria.Auth.Infrastructure.Persistence;
using Politoria.Contracts.Communication;

namespace Politoria.Auth.Infrastructure.Services;

/// <summary>
/// req/004 — email+password auth with mandatory email-OTP. Publishes auth emails
/// (OTP / set-password / reset) as <see cref="SendEmail"/> commands for
/// Hrms.Communication (Resend) to deliver. BCrypt for hashing.
/// </summary>
public class PasswordAuthService(
    AuthDbContext db,
    IPublishEndpoint bus,
    IConfiguration config,
    ILogger<PasswordAuthService> logger) : IPasswordAuthService
{
    private static readonly TimeSpan OtpTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan ResetTtl = TimeSpan.FromHours(1);
    private static readonly TimeSpan InviteTtl = TimeSpan.FromHours(72);

    private string Brand => config["Branding:ProductName"] ?? "Pishro";
    private string PublicUrl => (config["Auth:PublicUrl"] ?? "").TrimEnd('/');

    public async Task RegisterAsync(string email, string password, string displayName, CancellationToken ct)
    {
        var norm = email.Trim().ToLowerInvariant();

        // No enumeration: respond identically whether or not the email exists. If it
        // does, send a heads-up (sign in / reset) rather than creating a second account.
        if (await db.Users.AnyAsync(u => u.Email != null && u.Email.ToLower() == norm, ct))
        {
            await PublishEmail(norm, $"You already have a {Brand} account",
                $"<p>Someone tried to register a {Brand} account with this email, but one already exists.</p><p>If that was you, just sign in — or reset your password if you've forgotten it.</p>",
                $"You already have a {Brand} account. Sign in, or reset your password.", ct);
            return;
        }

        var user = User.Create(displayName.Trim());
        user.Update(email: norm);
        user.SetPasswordHash(BCrypt.Net.BCrypt.HashPassword(password));
        db.Users.Add(user);
        await IssueOtpAsync(user.Id, norm, ct);
    }

    public async Task<bool> RequestLoginAsync(string email, string password, CancellationToken ct)
    {
        var norm = email.Trim().ToLowerInvariant();
        var user = await db.Users.FirstOrDefaultAsync(u => u.Email != null && u.Email.ToLower() == norm, ct);
        if (user is null || !user.IsActive || string.IsNullOrEmpty(user.PasswordHash)
            || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            return false;

        await IssueOtpAsync(user.Id, norm, ct);
        return true;
    }

    // Create + email a fresh 6-digit sign-in OTP. Shared by login + self-signup.
    private async Task IssueOtpAsync(Guid userId, string email, CancellationToken ct)
    {
        var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        db.EmailOtpTokens.Add(EmailOtpToken.Create(userId, email, code, OtpTtl));
        await db.SaveChangesAsync(ct);

        await PublishEmail(email, $"Your {Brand} sign-in code",
            $"<p>Your {Brand} sign-in code is <strong>{code}</strong>.</p><p>It expires in 5 minutes. If you didn't try to sign in, you can ignore this email.</p>",
            $"Your {Brand} sign-in code is {code}. It expires in 5 minutes.", ct);
    }

    public async Task<SignedInUser?> VerifyOtpAsync(string email, string code, CancellationToken ct)
    {
        var norm = email.Trim().ToLowerInvariant();
        var token = await db.EmailOtpTokens
            .Where(t => t.Email == norm && !t.IsUsed)
            .OrderByDescending(t => t.CreatedAt)
            .FirstOrDefaultAsync(ct);
        if (token is null || !token.IsLive) return null;

        token.RecordAttempt();
        if (!token.Matches(code))
        {
            await db.SaveChangesAsync(ct);
            return null;
        }

        token.MarkUsed();
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == token.UserId, ct);
        if (user is null) { await db.SaveChangesAsync(ct); return null; }
        user.RecordLogin();
        await db.SaveChangesAsync(ct);
        return new SignedInUser(user.Id, user.DisplayName, user.Email, user.Phone);
    }

    public async Task<bool> SetPasswordAsync(string token, string newPassword, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(newPassword) || newPassword.Length < 8) return false;
        var row = await db.PasswordSetupTokens.FirstOrDefaultAsync(t => t.Token == token, ct);
        if (row is null || !row.IsLive) return false;
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == row.UserId, ct);
        if (user is null) return false;

        user.SetPasswordHash(BCrypt.Net.BCrypt.HashPassword(newPassword));
        row.MarkUsed();
        await db.SaveChangesAsync(ct);
        return true;
    }

    public async Task RequestResetAsync(string email, CancellationToken ct)
    {
        var norm = email.Trim().ToLowerInvariant();
        var user = await db.Users.FirstOrDefaultAsync(u => u.Email != null && u.Email.ToLower() == norm, ct);
        if (user is null || string.IsNullOrEmpty(user.Email)) return; // silent (no enumeration)
        await IssueAndEmail(user.Id, user.Email, ResetTtl, $"Reset your {Brand} password", "reset", ct);
    }

    public Task IssueSetupInviteAsync(Guid userId, string email, CancellationToken ct) =>
        IssueAndEmail(userId, email, InviteTtl, $"Set your {Brand} password", "set up", ct);

    private async Task IssueAndEmail(Guid userId, string email, TimeSpan ttl, string subject, string verb, CancellationToken ct)
    {
        var token = Base64Url(RandomNumberGenerator.GetBytes(32));
        db.PasswordSetupTokens.Add(PasswordSetupToken.Create(userId, token, ttl));
        await db.SaveChangesAsync(ct);

        var link = $"{PublicUrl}/set-password.html?token={token}";
        await PublishEmail(email, subject,
            $"<p>Use the link below to {verb} your {Brand} password:</p><p><a href=\"{link}\">{link}</a></p><p>If you didn't request this, you can ignore this email.</p>",
            $"To {verb} your {Brand} password, open: {link}", ct);
    }

    private async Task PublishEmail(string to, string subject, string html, string text, CancellationToken ct)
    {
        logger.LogInformation("Auth email → {To}: {Subject}", to, subject);
        try
        {
            await bus.Publish(new SendEmail(to, subject, html, text), ct);
        }
        catch (Exception ex)
        {
            // Email is a best-effort side-effect: by the time we publish, the OTP /
            // setup / reset token is already persisted. A transient broker outage must
            // NOT fail the auth operation (login/reset/setup) — log loudly and continue
            // so the caller still gets requiresOtp and can resend, rather than a 500.
            // (req/004 C1 caught a RabbitMQ outage 500-ing every email+password login.)
            logger.LogError(ex, "Failed to publish auth email to {To} ({Subject}); token persisted, delivery skipped.", to, subject);
        }
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
}
