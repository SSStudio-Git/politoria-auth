using System.ComponentModel.DataAnnotations;

namespace Politoria.Auth.Domain.Entities;

public class PasskeyCredential : BaseEntity
{
    public Guid UserId { get; private set; }

    public required byte[] CredentialId { get; init; }

    public required byte[] PublicKey { get; init; }

    public required byte[] UserHandle { get; init; }

    public uint SignatureCounter { get; private set; }

    public Guid AaGuid { get; private set; }

    [MaxLength(200)]
    public string? DeviceName { get; private set; }

    public DateTimeOffset? LastUsedAt { get; private set; }

    public bool IsActive { get; private set; } = true;

    public User User { get; private set; } = null!;

    private PasskeyCredential() { }

    public static PasskeyCredential Create(
        Guid userId,
        byte[] credentialId,
        byte[] publicKey,
        byte[] userHandle,
        uint signatureCounter,
        Guid aaGuid,
        string? deviceName = null)
    {
        return new PasskeyCredential
        {
            UserId = userId,
            CredentialId = credentialId,
            PublicKey = publicKey,
            UserHandle = userHandle,
            SignatureCounter = signatureCounter,
            AaGuid = aaGuid,
            DeviceName = deviceName
        };
    }

    public void UpdateCounter(uint newCounter)
    {
        SignatureCounter = newCounter;
        LastUsedAt = DateTimeOffset.UtcNow;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void Deactivate()
    {
        IsActive = false;
        UpdatedAt = DateTimeOffset.UtcNow;
    }
}
