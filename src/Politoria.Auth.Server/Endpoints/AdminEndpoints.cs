using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using Politoria.Auth.Application.Services;
using Politoria.Auth.Domain.Entities;
using Politoria.Auth.Infrastructure.Persistence;
using Politoria.Auth.Infrastructure.Seed;

namespace Politoria.Auth.Server.Endpoints;

/// <summary>
/// Service-to-service administrative endpoints. Called by HRMS Identity for
/// member-lifecycle operations that need to land in the IdP atomically:
/// creating a User row before a passkey is bound (break-glass + invite
/// handoff), polling whether the passkey has been registered, and cascading
/// hard-deletes.
///
/// Auth: OAuth2 client_credentials bearer tokens scoped to the matching
/// fine-grained <c>pishro-auth.admin.&lt;domain&gt;.&lt;action&gt;</c> scope.
/// The legacy <c>X-Admin-Key</c> header was retired in Harmonization
/// Wave A once break-glass shipped the synthetic test seam needed to
/// verify the bearer cascade end-to-end on prod.
/// </summary>
public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/admin");

        // POST /api/admin/users — pre-provision a User row with admin-supplied
        // identity data (no credentials yet). The caller (HRMS break-glass
        // flow, Identity invite-handoff flow) then signs an InviteHandoff
        // token carrying this Id and redirects the new member's browser to
        // /invite/register.html where the existing WebAuthn registration
        // ceremony binds the passkey.
        group.MapPost("/users", async (
            HttpContext httpContext,
            CreateUserRequest request,
            AuthDbContext db,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            var auth = await AuthorizeAsync(httpContext, ClientSeeder.AdminUsersCreateScope);
            if (auth is not null) return auth;

            var logger = loggerFactory.CreateLogger("AdminEndpoints");

            if (string.IsNullOrWhiteSpace(request.DisplayName))
                return Results.BadRequest(new { error = "displayName is required" });

            // Idempotency: if the caller pre-supplied an Id and that User
            // already exists, return the existing row. Otherwise create.
            User? user = null;
            if (request.Id is { } prebuiltId)
            {
                user = await db.Users.FirstOrDefaultAsync(u => u.Id == prebuiltId, ct);
            }

            if (user is null)
            {
                user = User.Create(request.DisplayName);
                if (request.Id is { } id)
                {
                    typeof(BaseEntity).GetProperty(nameof(BaseEntity.Id))!.SetValue(user, id);
                }
                if (request.Nickname is not null || request.Email is not null ||
                    request.Phone is not null || request.FirstName is not null ||
                    request.LastName is not null)
                {
                    user.Update(
                        nickname: request.Nickname,
                        firstName: request.FirstName,
                        lastName: request.LastName,
                        email: request.Email,
                        phone: request.Phone);
                }
                db.Users.Add(user);
                await db.SaveChangesAsync(ct);
                logger.LogInformation("Admin-created user {UserId} (displayName={DisplayName})", user.Id, user.DisplayName);
            }
            else
            {
                logger.LogInformation("Admin-create idempotent hit on existing user {UserId}", user.Id);
            }

            return Results.Ok(new
            {
                userId = user.Id,
                displayName = user.DisplayName,
                created = true,
            });
        }).WithName("AdminCreateUser");

        // POST /api/admin/users/{userId}/send-password-setup — req/004. For an
        // admin/invite-created user with an email, email a one-time "set your
        // password" link (the email+password credential path; passkey users use
        // the invite-handoff ceremony instead). Invite-only — no public signup.
        group.MapPost("/users/{userId:guid}/send-password-setup", async (
            HttpContext httpContext,
            Guid userId,
            AuthDbContext db,
            IPasswordAuthService passwordAuth,
            CancellationToken ct) =>
        {
            var auth = await AuthorizeAsync(httpContext, ClientSeeder.AdminUsersCreateScope);
            if (auth is not null) return auth;

            var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
            if (user is null) return Results.NotFound();
            if (string.IsNullOrWhiteSpace(user.Email))
                return Results.BadRequest(new { error = "User has no email address." });

            await passwordAuth.IssueSetupInviteAsync(user.Id, user.Email, ct);
            return Results.Ok(new { success = true });
        }).WithName("AdminSendPasswordSetup");

        // GET /api/admin/users/{userId}/status — used by HRMS during the
        // break-glass flow to poll until the new member has bound a passkey.
        // Returns 404 if the User row doesn't exist; otherwise reports
        // whether at least one active PasskeyCredential is on file.
        group.MapGet("/users/{userId:guid}/status", async (
            HttpContext httpContext,
            Guid userId,
            AuthDbContext db,
            CancellationToken ct) =>
        {
            var auth = await AuthorizeAsync(httpContext, ClientSeeder.AdminUsersReadScope);
            if (auth is not null) return auth;

            var user = await db.Users
                .Where(u => u.Id == userId)
                .Select(u => new { u.Id, u.DisplayName, u.IsActive })
                .FirstOrDefaultAsync(ct);
            if (user is null) return Results.NotFound();

            var firstPasskeyAt = await db.PasskeyCredentials
                .Where(p => p.UserId == userId && p.IsActive)
                .OrderBy(p => p.CreatedAt)
                .Select(p => (DateTimeOffset?)p.CreatedAt)
                .FirstOrDefaultAsync(ct);

            return Results.Ok(new
            {
                userId = user.Id,
                isActive = user.IsActive,
                passkeyRegistered = firstPasskeyAt.HasValue,
                passkeyRegisteredAt = firstPasskeyAt,
            });
        }).WithName("AdminGetUserStatus");

        // DELETE /api/admin/users/{userId} — cascade hard-delete from HRMS.
        // Bearer-only since Harmonization Wave A.
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
    /// Bearer-only since Harmonization Wave A. Returns null when authorized;
    /// otherwise an IResult to short-circuit with 401 / 403.
    /// </summary>
    private static async Task<IResult?> AuthorizeAsync(HttpContext httpContext, string requiredScope)
    {
        var authHeader = httpContext.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(authHeader) ||
            !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return Results.Unauthorized();
        }

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

    /// <summary>
    /// Body for POST /api/admin/users. <see cref="Id"/> is optional; supply
    /// it to make the call idempotent under retry (HRMS pre-allocates the
    /// IdentityId so its DB and pishro-auth's stay aligned).
    /// </summary>
    public sealed record CreateUserRequest(
        string DisplayName,
        Guid? Id = null,
        string? Nickname = null,
        string? FirstName = null,
        string? LastName = null,
        string? Email = null,
        string? Phone = null);
}
