using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Politoria.Auth.Application.Services;

namespace Politoria.Auth.Infrastructure.Services;

/// <summary>
/// HMAC-SHA256 verifier for invite handoff tokens. Token format:
///   base64url(payload_json) + "." + base64url(hmac_sha256(payload_json, secret))
/// where payload = { "sub": "identity-guid", "name": "display name", "exp": unix_seconds }
///
/// The shared secret lives in config as InviteHandoff:SharedSecret. HRMS signs
/// with the same secret when claimInvite() succeeds.
/// </summary>
public class InviteHandoffService(
    IConfiguration configuration,
    ILogger<InviteHandoffService> logger) : IInviteHandoffService
{
    private record Payload(string sub, string name, long exp, string? email = null);

    public InviteHandoff? Verify(string token)
    {
        var secret = configuration["InviteHandoff:SharedSecret"];
        if (string.IsNullOrEmpty(secret))
        {
            logger.LogError("InviteHandoff:SharedSecret is not configured");
            return null;
        }

        var parts = token.Split('.');
        if (parts.Length != 2)
        {
            logger.LogWarning("Invite handoff token is malformed");
            return null;
        }

        byte[] payloadBytes;
        byte[] providedSig;
        try
        {
            payloadBytes = Base64UrlDecode(parts[0]);
            providedSig = Base64UrlDecode(parts[1]);
        }
        catch
        {
            logger.LogWarning("Invite handoff token has invalid base64url encoding");
            return null;
        }

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var computedSig = hmac.ComputeHash(payloadBytes);

        if (!CryptographicOperations.FixedTimeEquals(computedSig, providedSig))
        {
            logger.LogWarning("Invite handoff token signature mismatch");
            return null;
        }

        Payload? payload;
        try
        {
            payload = JsonSerializer.Deserialize<Payload>(payloadBytes);
        }
        catch (JsonException ex)
        {
            logger.LogWarning(ex, "Invite handoff token payload is not valid JSON");
            return null;
        }

        if (payload is null || string.IsNullOrEmpty(payload.sub))
            return null;

        var nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (payload.exp <= nowUnix)
        {
            logger.LogWarning("Invite handoff token has expired (exp={Exp}, now={Now})", payload.exp, nowUnix);
            return null;
        }

        if (!Guid.TryParse(payload.sub, out var identityId))
        {
            logger.LogWarning("Invite handoff sub is not a valid Guid");
            return null;
        }

        return new InviteHandoff(identityId, payload.name ?? "User", payload.email);
    }

    private static byte[] Base64UrlDecode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }
}
