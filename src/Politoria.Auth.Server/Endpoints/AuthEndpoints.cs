using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Politoria.Auth.Application.Services;
using Politoria.Auth.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Politoria.Auth.Server.Endpoints;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/passkey");

        group.MapPost("/register/begin", async (
            JsonElement body,
            IPasskeyService passkeyService,
            CancellationToken ct) =>
        {
            var displayName = body.TryGetProperty("displayName", out var dn)
                ? dn.GetString() ?? "User"
                : "User";

            var result = await passkeyService.BeginRegisterAsync(displayName, ct: ct);
            return Results.Ok(result);
        });

        group.MapPost("/register/complete", async (
            JsonElement body,
            IPasskeyService passkeyService,
            AuthDbContext db,
            HttpContext httpContext,
            CancellationToken ct) =>
        {
            var result = await passkeyService.CompleteRegisterAsync(body, ct);
            if (result.Error == InviteAccountGuard.ExistingAccountError)
                return ExistingAccountConflict();
            if (!result.Success)
                return Results.BadRequest(new { error = result.Error });

            // Sign in with cookie
            var user = await db.Users.FirstOrDefaultAsync(u => u.Id == result.UserId, ct);
            if (user is null)
                return Results.BadRequest(new { error = "User not found after registration" });

            var claims = BuildClaims(user.Id, user.DisplayName, user.Email, user.Phone, LoginMethods.Passkey);
            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await httpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal);

            return Results.Ok(new { success = true, userId = result.UserId });
        });

        group.MapPost("/login/begin", async (
            IPasskeyService passkeyService,
            CancellationToken ct) =>
        {
            var result = await passkeyService.BeginLoginAsync(ct);
            return Results.Ok(result);
        });

        // HRMS invite handoff: begin passkey registration using the identityId
        // carried by an HMAC-signed handoff token. The token is issued by HRMS
        // when claimInvite() succeeds and binds the user to a VerifiedIdentity
        // that already exists in hrms_identity.
        group.MapPost("/invite/begin", async (
            JsonElement body,
            IPasskeyService passkeyService,
            IInviteHandoffService handoffService,
            CancellationToken ct) =>
        {
            if (!body.TryGetProperty("handoff", out var handoffElement))
                return Results.BadRequest(new { error = "Missing handoff" });

            var token = handoffElement.GetString();
            if (string.IsNullOrEmpty(token))
                return Results.BadRequest(new { error = "Empty handoff token" });

            var handoff = handoffService.Verify(token);
            if (handoff is null)
                return Results.BadRequest(new { error = "Invalid or expired handoff" });

            // The handoff email already belongs to another account (HRMS minted a
            // new identity id for an existing person): refuse rather than create a
            // second, email-less user next to it.
            if (await passkeyService.InviteEmailBelongsToOtherUserAsync(handoff.IdentityId, handoff.Email, ct))
                return ExistingAccountConflict();

            var result = await passkeyService.BeginRegisterAsync(
                handoff.DisplayName, handoff.IdentityId, handoff.Email, ct);
            return Results.Ok(result);
        });

        group.MapPost("/login/complete", async (
            JsonElement body,
            IPasskeyService passkeyService,
            AuthDbContext db,
            HttpContext httpContext,
            CancellationToken ct) =>
        {
            var result = await passkeyService.CompleteLoginAsync(body, ct);
            if (!result.Success)
                return Results.BadRequest(new { error = result.Error });

            var user = await db.Users.FirstOrDefaultAsync(u => u.Id == result.UserId, ct);
            if (user is null)
                return Results.BadRequest(new { error = "User not found" });

            var claims = BuildClaims(user.Id, user.DisplayName, user.Email, user.Phone, LoginMethods.Passkey);
            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await httpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal);

            return Results.Ok(new { success = true, userId = result.UserId });
        });
    }

    internal static IResult ExistingAccountConflict() =>
        Results.Json(
            new { error = InviteAccountGuard.ExistingAccountError, message = InviteAccountGuard.ExistingAccountMessage },
            statusCode: StatusCodes.Status409Conflict);

    internal static List<Claim> BuildClaims(
        Guid userId, string? displayName, string? email, string? phone, string method)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new("sub", userId.ToString())
        };

        if (!string.IsNullOrEmpty(displayName))
            claims.Add(new Claim("name", displayName));
        if (!string.IsNullOrEmpty(email))
            claims.Add(new Claim(ClaimTypes.Email, email));
        if (!string.IsNullOrEmpty(phone))
            claims.Add(new Claim("phone_number", phone));

        // How this browser session was opened. Carried into the authorization
        // code by HandleAuthorize so the sign-in record says passkey or password.
        claims.Add(new Claim(LoginMethods.ClaimType, method));

        return claims;
    }
}
