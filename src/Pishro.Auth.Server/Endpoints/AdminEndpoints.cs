using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using Pishro.Auth.Infrastructure.Persistence;
using Pishro.Auth.Infrastructure.Seed;

namespace Pishro.Auth.Server.Endpoints;

/// <summary>
/// Service-to-service administrative endpoints. Called by the HRMS Identity
/// service when a member is hard-deleted so the user + their passkey
/// credentials are removed from the IdP too.
///
/// Auth: OAuth2 client_credentials bearer tokens scoped to the matching
/// fine-grained <c>pishro-auth.admin.&lt;domain&gt;.&lt;action&gt;</c> scope.
/// During the cutover from the legacy <c>X-Admin-Key</c> header, both auth
/// methods are accepted; the header path will be removed in PR 3 once HRMS
/// has been verified on the bearer flow in production.
/// </summary>
public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/admin");

        group.MapDelete("/users/{userId:guid}", async (
            HttpContext httpContext,
            Guid userId,
            AuthDbContext db,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            var auth = await AuthorizeAsync(httpContext, ClientSeeder.AdminUsersDeleteScope);
            if (auth is not null) return auth;

            var logger = loggerFactory.CreateLogger("AdminEndpoints");
            var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
            if (user is null) return Results.NotFound();

            // passkey_credentials FK has ON DELETE CASCADE — removing the user
            // row clears the WebAuthn credentials in the same transaction.
            db.Users.Remove(user);
            await db.SaveChangesAsync(ct);

            logger.LogInformation("Admin-deleted user {UserId} (passkeys cascade-removed)", userId);
            return Results.Ok(new { deleted = true });
        }).WithName("AdminDeleteUser");
    }

    /// <summary>
    /// Try the bearer path first; on miss, fall back to the legacy header.
    /// Returns null when authorized; otherwise an IResult to short-circuit
    /// the endpoint with 401 / 403 / 503.
    /// </summary>
    private static async Task<IResult?> AuthorizeAsync(HttpContext httpContext, string requiredScope)
    {
        var authHeader = httpContext.Request.Headers.Authorization.ToString();
        if (!string.IsNullOrEmpty(authHeader) &&
            authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var result = await httpContext.AuthenticateAsync(
                OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);

            if (!result.Succeeded || result.Principal is null)
            {
                return Results.Unauthorized();
            }

            if (!HasScope(result.Principal, requiredScope))
            {
                return Results.Forbid();
            }

            httpContext.User = result.Principal;
            return null;
        }

        return AuthorizeWithLegacyHeader(httpContext);
    }

    /// <summary>
    /// Pre-OIDC fallback. Removed in PR 3 once HRMS has cut over.
    /// </summary>
    private static IResult? AuthorizeWithLegacyHeader(HttpContext httpContext)
    {
        var configured = httpContext.RequestServices
            .GetRequiredService<IConfiguration>()["Admin:Key"];

        if (string.IsNullOrWhiteSpace(configured))
        {
            // Misconfigured AND no bearer presented — fail closed.
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        }

        var presented = httpContext.Request.Headers["X-Admin-Key"].ToString();
        if (string.IsNullOrEmpty(presented))
        {
            return Results.Unauthorized();
        }

        if (!string.Equals(presented, configured, StringComparison.Ordinal))
        {
            return Results.Unauthorized();
        }

        return null;
    }

    private static bool HasScope(ClaimsPrincipal principal, string scope)
    {
        // OpenIddict serializes granted scopes as a single space-separated
        // claim of type oi_scp; HasScope() inspects that.
        foreach (var claim in principal.FindAll(OpenIddictConstants.Claims.Private.Scope))
        {
            if (claim.Value == scope) return true;
        }
        // Fallback: standard `scope` claim (single value or space-joined).
        var scopeClaim = principal.FindFirst(OpenIddictConstants.Claims.Scope)?.Value;
        if (string.IsNullOrEmpty(scopeClaim)) return false;
        foreach (var s in scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (s == scope) return true;
        }
        return false;
    }
}
