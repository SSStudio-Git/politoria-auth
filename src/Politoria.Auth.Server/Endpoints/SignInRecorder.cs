using System.Security.Claims;
using MassTransit;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using Politoria.Auth.Infrastructure.Persistence;
using Politoria.Contracts.Identity;

namespace Politoria.Auth.Server.Endpoints;

/// <summary>
/// Tells HRMS that a person opened a session in one of the clients (the ERP,
/// the portal), so administrators can see who has actually signed in. Before
/// this, auth kept only <c>users.last_login_at</c>, overwritten every time.
///
/// Recording is best effort: a broker outage must never cost anyone a login,
/// so a failed publish is logged and swallowed.
/// </summary>
public sealed class SignInRecorder(IPublishEndpoint bus, ILogger<SignInRecorder> logger)
{
    public const string MethodClaim = "login_method";
    public const string DeviceClaim = "login_device";

    public async Task RecordAsync(ClaimsPrincipal principal, string? clientId, CancellationToken ct)
    {
        if (!Guid.TryParse(principal.FindFirstValue(OpenIddictConstants.Claims.Subject), out var identityId)
            || string.IsNullOrEmpty(clientId))
            return;

        try
        {
            await bus.Publish(new UserSignedInEvent
            {
                IdentityId = identityId,
                ClientId = clientId,
                Method = principal.FindFirstValue(MethodClaim),
                Device = principal.FindFirstValue(DeviceClaim),
                OccurredAt = DateTimeOffset.UtcNow,
            }, ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not record the sign-in of {IdentityId} to {ClientId}", identityId, clientId);
        }
    }

    /// <summary>
    /// "Chrome on Windows" — browser family and OS only. The full user-agent
    /// string is a fingerprint and is deliberately not kept.
    /// </summary>
    public static string? DeviceOf(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent)) return null;
        var ua = userAgent;

        string? browser =
            ua.Contains("Edg/", StringComparison.Ordinal) ? "Edge"
            : ua.Contains("OPR/", StringComparison.Ordinal) ? "Opera"
            : ua.Contains("Firefox/", StringComparison.Ordinal) || ua.Contains("FxiOS/", StringComparison.Ordinal) ? "Firefox"
            : ua.Contains("Chrome/", StringComparison.Ordinal) || ua.Contains("CriOS/", StringComparison.Ordinal) ? "Chrome"
            : ua.Contains("Safari/", StringComparison.Ordinal) ? "Safari"
            : null;

        string? os =
            ua.Contains("iPhone", StringComparison.Ordinal) || ua.Contains("iPad", StringComparison.Ordinal) ? "iOS"
            : ua.Contains("Android", StringComparison.Ordinal) ? "Android"
            : ua.Contains("Windows", StringComparison.Ordinal) ? "Windows"
            : ua.Contains("Mac OS X", StringComparison.Ordinal) || ua.Contains("Macintosh", StringComparison.Ordinal) ? "macOS"
            : ua.Contains("Linux", StringComparison.Ordinal) ? "Linux"
            : null;

        return (browser, os) switch
        {
            (null, null) => null,
            (not null, null) => browser,
            (null, not null) => os,
            _ => $"{browser} on {os}",
        };
    }
}

/// <summary>
/// Sends every user's last sign-in from before tracking existed, once per
/// start, marked <see cref="UserSignedInEvent.Backfilled"/>. HRMS only moves
/// a person's "last sign-in" forward with these and never writes a history
/// row for them, so repeating it on each restart is harmless.
/// </summary>
public sealed class SignInBackfill(IServiceScopeFactory scopes, ILogger<SignInBackfill> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            // Let the bus finish connecting before the first publish.
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
            var bus = scope.ServiceProvider.GetRequiredService<IPublishEndpoint>();

            var last = await db.Users.AsNoTracking()
                .Where(u => u.LastLoginAt != null)
                .Select(u => new { u.Id, u.LastLoginAt })
                .ToListAsync(stoppingToken);

            foreach (var u in last)
                await bus.Publish(new UserSignedInEvent
                {
                    IdentityId = u.Id,
                    ClientId = "unknown",
                    OccurredAt = u.LastLoginAt!.Value,
                    Backfilled = true,
                }, stoppingToken);

            logger.LogInformation("Sign-in backfill: sent the last sign-in of {Count} users", last.Count);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Sign-in backfill failed");
        }
    }
}
