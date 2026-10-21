namespace Politoria.Contracts.Identity;

/// <summary>
/// Local mirror of the platform <c>UserSignedInEvent</c> (politoria-contracts,
/// Identity/UserSignedInEvent.cs). Namespace + type name match exactly so
/// MassTransit routes it to the same exchange HRMS IAM binds to — the same
/// arrangement as <see cref="Politoria.Contracts.Communication.SendEmail"/>.
/// Keep the two in step.
/// </summary>
public record UserSignedInEvent
{
    public required Guid IdentityId { get; init; }
    public required string ClientId { get; init; }
    public string? Method { get; init; }
    public string? Device { get; init; }
    public required DateTimeOffset OccurredAt { get; init; }
    public bool Backfilled { get; init; }
}
