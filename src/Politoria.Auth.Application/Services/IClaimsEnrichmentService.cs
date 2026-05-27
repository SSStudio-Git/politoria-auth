using System.Security.Claims;

namespace Politoria.Auth.Application.Services;

/// <summary>
/// Enriches OIDC token claims by fetching roles and vetting status
/// from HRMS internal endpoints at token issuance time.
/// </summary>
public interface IClaimsEnrichmentService
{
    /// <summary>
    /// Fetches roles, permissions, and vetting status for a user from HRMS
    /// and returns them as claims to include in the OIDC token.
    /// </summary>
    Task<IReadOnlyList<Claim>> GetEnrichedClaimsAsync(Guid userId, CancellationToken ct = default);
}
