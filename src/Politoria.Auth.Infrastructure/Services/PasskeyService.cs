using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Politoria.Auth.Application.DTOs;
using Politoria.Auth.Application.Services;
using Politoria.Auth.Domain.Entities;
using Politoria.Auth.Infrastructure.Persistence;

namespace Politoria.Auth.Infrastructure.Services;

public class PasskeyService(
    AuthDbContext db,
    IFido2 fido2,
    IDistributedCache cache) : IPasskeyService
{
    private static readonly TimeSpan ChallengeExpiry = TimeSpan.FromMinutes(5);
    private const string RegisterPrefix = "fido2:reg:";
    private const string LoginPrefix = "fido2:login:";

    public async Task<object> BeginRegisterAsync(string displayName, Guid? userId = null, CancellationToken ct = default)
    {
        var effectiveUserId = userId ?? Guid.NewGuid();
        var userHandle = effectiveUserId.ToByteArray();

        var user = new Fido2User
        {
            Id = userHandle,
            Name = displayName,
            DisplayName = displayName
        };

        // ResidentKey = Required is non-negotiable: the login flow uses
        // AllowedCredentials = [] (a usernameless / discoverable-credential
        // flow), so a non-discoverable credential created here would be
        // unreachable at sign-in time — the browser wouldn't even surface
        // it. The library's default is Preferred, which lets some
        // authenticators (notably external hardware keys) decide to skip
        // resident storage. Pin it.
        var options = fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = user,
            ExcludeCredentials = [],
            AuthenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = ResidentKeyRequirement.Required,
                // Require user verification (biometric/PIN) — true MFA, not just key presence.
                UserVerification = UserVerificationRequirement.Required,
            },
            AttestationPreference = AttestationConveyancePreference.None
        });

        var challengeId = Guid.NewGuid().ToString();
        var optionsJson = options.ToJson();

        var payload = JsonSerializer.Serialize(new { optionsJson, userId = effectiveUserId, displayName });
        await cache.SetStringAsync(
            RegisterPrefix + challengeId,
            payload,
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ChallengeExpiry },
            ct);

        using var browserDoc = JsonDocument.Parse(optionsJson);
        return new { challengeId, options = browserDoc.RootElement.Clone() };
    }

    public async Task<AuthResult> CompleteRegisterAsync(JsonElement request, CancellationToken ct)
    {
        if (!request.TryGetProperty("challengeId", out var challengeIdElement))
            return new AuthResult(false, null, "Missing challengeId");

        var challengeId = challengeIdElement.GetString();
        if (string.IsNullOrEmpty(challengeId))
            return new AuthResult(false, null, "Invalid challengeId");

        var payloadJson = await cache.GetStringAsync(RegisterPrefix + challengeId, ct);
        if (payloadJson is null)
            return new AuthResult(false, null, "Challenge expired or invalid");

        using var payloadDoc = JsonDocument.Parse(payloadJson);
        var optionsJson = payloadDoc.RootElement.GetProperty("optionsJson").GetString()!;
        var userId = payloadDoc.RootElement.GetProperty("userId").GetGuid();
        var displayName = payloadDoc.RootElement.GetProperty("displayName").GetString()!;

        var options = CredentialCreateOptions.FromJson(optionsJson);

        if (!request.TryGetProperty("attestationResponse", out var attestationElement))
            return new AuthResult(false, null, "Missing attestationResponse");

        AuthenticatorAttestationRawResponse? attestationResponse;
        try
        {
            attestationResponse = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(
                attestationElement.GetRawText());
        }
        catch (JsonException ex)
        {
            return new AuthResult(false, null, $"Could not parse attestation: {ex.Message}");
        }

        if (attestationResponse is null)
            return new AuthResult(false, null, "Empty attestation response");

        try
        {
            var result = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = attestationResponse,
                OriginalOptions = options,
                IsCredentialIdUniqueToUserCallback = async (args, token) =>
                {
                    var exists = await db.PasskeyCredentials
                        .AnyAsync(p => p.CredentialId == args.CredentialId, token);
                    return !exists;
                }
            }, ct);

            // Create the user unless one already exists for this Id (idempotent;
            // handles HRMS invite handoffs and already-migrated users)
            var existingUser = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
            if (existingUser is null)
            {
                var user = User.Create(displayName);
                typeof(BaseEntity).GetProperty(nameof(BaseEntity.Id))!
                    .SetValue(user, userId);
                db.Users.Add(user);
            }

            var credential = PasskeyCredential.Create(
                userId: userId,
                credentialId: result.Id,
                publicKey: result.PublicKey,
                userHandle: result.User.Id,
                signatureCounter: result.SignCount,
                aaGuid: result.AaGuid);

            db.PasskeyCredentials.Add(credential);
            await db.SaveChangesAsync(ct);
            await cache.RemoveAsync(RegisterPrefix + challengeId, ct);

            return new AuthResult(true, userId, null);
        }
        catch (Exception ex)
        {
            return new AuthResult(false, null, $"Attestation verification failed: {ex.Message}");
        }
    }

    public async Task<object> BeginLoginAsync(CancellationToken ct)
    {
        var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = [],
            // Require user verification (biometric/PIN) on every login assertion.
            UserVerification = UserVerificationRequirement.Required
        });

        var challengeId = Guid.NewGuid().ToString();
        var optionsJson = options.ToJson();
        await cache.SetStringAsync(
            LoginPrefix + challengeId,
            optionsJson,
            new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = ChallengeExpiry },
            ct);

        return new { challengeId, options };
    }

    public async Task<AuthResult> CompleteLoginAsync(JsonElement request, CancellationToken ct)
    {
        if (!request.TryGetProperty("challengeId", out var challengeIdElement))
            return new AuthResult(false, null, "Missing challengeId");

        var challengeId = challengeIdElement.GetString();
        if (string.IsNullOrEmpty(challengeId))
            return new AuthResult(false, null, "Invalid challengeId");

        var optionsJson = await cache.GetStringAsync(LoginPrefix + challengeId, ct);
        if (optionsJson is null)
            return new AuthResult(false, null, "Challenge expired or invalid");

        var options = AssertionOptions.FromJson(optionsJson);

        if (!request.TryGetProperty("assertionResponse", out var assertionElement))
            return new AuthResult(false, null, "Missing assertionResponse");

        AuthenticatorAssertionRawResponse? assertionResponse;
        try
        {
            assertionResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(
                assertionElement.GetRawText());
        }
        catch (JsonException ex)
        {
            return new AuthResult(false, null, $"Could not parse assertion: {ex.Message}");
        }

        if (assertionResponse is null)
            return new AuthResult(false, null, "Empty assertion response");

        var storedCredential = await db.PasskeyCredentials
            .Include(p => p.User)
            .FirstOrDefaultAsync(p => p.CredentialId == assertionResponse.RawId, ct);

        if (storedCredential is null || !storedCredential.IsActive)
            return new AuthResult(false, null, "Unknown or inactive credential");

        try
        {
            var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = assertionResponse,
                OriginalOptions = options,
                StoredPublicKey = storedCredential.PublicKey,
                StoredSignatureCounter = storedCredential.SignatureCounter,
                IsUserHandleOwnerOfCredentialIdCallback = async (args, token) =>
                {
                    var cred = await db.PasskeyCredentials
                        .FirstOrDefaultAsync(p => p.CredentialId == args.CredentialId, token);
                    return cred is not null && cred.UserHandle.SequenceEqual(args.UserHandle);
                }
            }, ct);

            storedCredential.UpdateCounter(result.SignCount);
            storedCredential.User.RecordLogin();
            await db.SaveChangesAsync(ct);
            await cache.RemoveAsync(LoginPrefix + challengeId, ct);

            return new AuthResult(true, storedCredential.UserId, null);
        }
        catch (Exception ex)
        {
            return new AuthResult(false, null, $"Assertion verification failed: {ex.Message}");
        }
    }
}
