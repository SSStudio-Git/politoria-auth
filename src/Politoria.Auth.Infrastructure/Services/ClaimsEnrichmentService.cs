using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Politoria.Auth.Application.Services;

namespace Politoria.Auth.Infrastructure.Services;

/// <summary>
/// Enriches OIDC tokens by fetching roles and vetting status from HRMS
/// internal API endpoints at token issuance time.
/// pishro-auth does NOT store roles/permissions — HRMS IAM is the source of truth.
/// </summary>
public class ClaimsEnrichmentService(
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration,
    ILogger<ClaimsEnrichmentService> logger) : IClaimsEnrichmentService
{
    private record RolesResponse(string[] Roles, string? VettingStatus, Guid[]? TenantIds, string[]? Permissions);
    private record VettingStatusResponse(string VettingStatus);

    public async Task<IReadOnlyList<Claim>> GetEnrichedClaimsAsync(Guid userId, CancellationToken ct = default)
    {
        var claims = new List<Claim>();

        var iamBaseUrl = configuration["Hrms:IamBaseUrl"];
        var identityBaseUrl = configuration["Hrms:IdentityBaseUrl"];

        // If HRMS endpoints are not configured, return empty (portal-only mode)
        if (string.IsNullOrEmpty(iamBaseUrl) && string.IsNullOrEmpty(identityBaseUrl))
            return claims;

        var client = httpClientFactory.CreateClient("hrms-internal");

        // Fetch roles from HRMS IAM
        if (!string.IsNullOrEmpty(iamBaseUrl))
        {
            try
            {
                var rolesResponse = await client.GetFromJsonAsync<RolesResponse>(
                    $"{iamBaseUrl}/api/iam/internal/roles/{userId}", ct);

                if (rolesResponse is not null)
                {
                    foreach (var role in rolesResponse.Roles)
                    {
                        claims.Add(new Claim("role", role));
                    }

                    // Emit a single boolean `hrms_access` claim rather than the
                    // full permission list. The super-admin role has ~160 permissions
                    // which bloats the id_token past nginx's 4 KB upstream buffer
                    // (causing 502 on the callback). Fine-grained checks should
                    // query /api/iam/internal/roles server-side when needed.
                    var hasBackofficeAccess = rolesResponse.Permissions is { Length: > 0 } &&
                        rolesResponse.Permissions.Any(p =>
                            string.Equals(p, "hrms.backoffice:access", StringComparison.OrdinalIgnoreCase));
                    if (hasBackofficeAccess)
                    {
                        claims.Add(new Claim("hrms_access", "true"));
                    }

                    // Second boolean claim: surfaces members.sensitive-data:read so
                    // Hrms.SharedKernel.ICurrentUser.HasSensitiveAccess can drive the
                    // MemberSerializer full-vs-masked projection. Same shrinkage rationale
                    // as hrms_access — no per-permission claim explosion.
                    var hasSensitiveAccess = rolesResponse.Permissions is { Length: > 0 } &&
                        rolesResponse.Permissions.Any(p =>
                            string.Equals(p, "members.sensitive-data:read", StringComparison.OrdinalIgnoreCase));
                    if (hasSensitiveAccess)
                    {
                        claims.Add(new Claim("has_sensitive_access", "true"));
                    }

                    // Third boolean claim: surfaces system.backoffice:full-access.
                    // Replaces the four hardcoded "if role == super-admin" bypasses
                    // in HRMS (DocumentAccessGuard, OrgUnitAccessChecker,
                    // TenantQueryExtensions, OrgUnitEndpoints). Admins now grant
                    // blanket access via this explicit permission instead of by
                    // role name — read in code via ICurrentUser.HasFullAccess.
                    var hasFullAccess = rolesResponse.Permissions is { Length: > 0 } &&
                        rolesResponse.Permissions.Any(p =>
                            string.Equals(p, "system.backoffice:full-access", StringComparison.OrdinalIgnoreCase));
                    if (hasFullAccess)
                    {
                        claims.Add(new Claim("full_access", "true"));
                    }

                    // HRMS reads `tenant_ids` (plural, comma-separated) via
                    // CurrentUser.TenantIds. The IAM internal endpoint returns
                    // a `tenantIds` array — preserve that shape end-to-end.
                    if (rolesResponse.TenantIds is { Length: > 0 })
                        claims.Add(new Claim("tenant_ids", string.Join(",", rolesResponse.TenantIds)));

                    if (!string.IsNullOrEmpty(rolesResponse.VettingStatus))
                        claims.Add(new Claim("vetting_status", rolesResponse.VettingStatus));
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to fetch roles from HRMS IAM for user {UserId}", userId);
            }
        }

        // Fetch vetting status from HRMS Identity (fallback if IAM didn't provide it)
        if (!claims.Exists(c => c.Type == "vetting_status") && !string.IsNullOrEmpty(identityBaseUrl))
        {
            try
            {
                var vettingResponse = await client.GetFromJsonAsync<VettingStatusResponse>(
                    $"{identityBaseUrl}/api/identity/internal/vetting-status/{userId}", ct);

                if (vettingResponse is not null && !string.IsNullOrEmpty(vettingResponse.VettingStatus))
                    claims.Add(new Claim("vetting_status", vettingResponse.VettingStatus));
            }
            catch (System.Net.Http.HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                // Expected: identities without a verified-identity row (e.g. invite-only
                // or IAM-only users) have no vetting status. Not an error — leave the
                // claim absent (the vetting middleware treats absent as "not blocked").
                logger.LogDebug("No verified-identity vetting status for user {UserId} (404)", userId);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to fetch vetting status from HRMS Identity for user {UserId}", userId);
            }
        }

        // Harmonization Wave B — fetch OrgUnit affiliations from HRMS
        // Organization. Emitted as a comma-separated `org_units` claim
        // mirroring the `tenant_ids` shape. Drives ForOrgUnits<T> +
        // RequireOrgUnitPermission on workspace endpoints. Claim is
        // omitted when the user isn't affiliated with any unit.
        var organizationBaseUrl = configuration["Hrms:OrganizationBaseUrl"];
        if (!string.IsNullOrEmpty(organizationBaseUrl))
        {
            try
            {
                var unitIds = await client.GetFromJsonAsync<Guid[]>(
                    $"{organizationBaseUrl}/api/organization/internal/unit-ids-for-member/{userId}", ct);
                if (unitIds is { Length: > 0 })
                {
                    claims.Add(new Claim("org_units", string.Join(",", unitIds)));
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to fetch OrgUnits from HRMS Organization for user {UserId}", userId);
            }
        }

        return claims;
    }
}
