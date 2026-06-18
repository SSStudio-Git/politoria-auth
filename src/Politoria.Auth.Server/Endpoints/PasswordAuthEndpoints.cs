using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Politoria.Auth.Application.Services;

namespace Politoria.Auth.Server.Endpoints;

/// <summary>
/// req/004 — email + password authentication with a mandatory email-OTP second
/// step. On a verified OTP it signs the SAME cookie the passkey flow uses, so the
/// browser resumes /connect/authorize and the OIDC clients are unchanged. Account
/// creation stays invite/admin-only (no signup endpoint here).
/// </summary>
public static class PasswordAuthEndpoints
{
    public static void MapPasswordAuthEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/password").RequireRateLimiting("auth");

        // Public self-signup: create an email+password account → send confirmation OTP.
        // Always returns requiresOtp (no enumeration); the portal's OIDC callback turns
        // the first verified sign-in into a PendingVetting member.
        group.MapPost("/register", async (
            JsonElement body, IPasswordAuthService svc, CancellationToken ct) =>
        {
            var email = body.TryGetProperty("email", out var re) ? re.GetString()?.Trim() : null;
            var password = body.TryGetProperty("password", out var rp) ? rp.GetString() : null;
            var displayName = body.TryGetProperty("displayName", out var rd) ? rd.GetString()?.Trim() : null;
            if (string.IsNullOrWhiteSpace(displayName) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
                return Results.BadRequest(new { error = "Name, email, and password are required." });
            if (!email.Contains('@') || email.Length > 200)
                return Results.BadRequest(new { error = "Enter a valid email address." });
            if (!PasswordPolicy.IsAcceptable(password, out var pwError))
                return Results.BadRequest(new { error = pwError });

            await svc.RegisterAsync(email, password, displayName, ct);
            return Results.Ok(new { requiresOtp = true, email });
        });

        // Resend the sign-in OTP (in-progress login/signup). Always 200 (no enumeration).
        group.MapPost("/resend-otp", async (
            JsonElement body, IPasswordAuthService svc, CancellationToken ct) =>
        {
            var email = body.TryGetProperty("email", out var e) ? e.GetString() : null;
            if (!string.IsNullOrWhiteSpace(email))
                await svc.ResendOtpAsync(email, ct);
            return Results.Ok(new { sent = true });
        });

        // Step 1: email + password → send OTP.
        group.MapPost("/login", async (
            JsonElement body, IPasswordAuthService svc, CancellationToken ct) =>
        {
            var email = body.TryGetProperty("email", out var e) ? e.GetString() : null;
            var password = body.TryGetProperty("password", out var p) ? p.GetString() : null;
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
                return Results.BadRequest(new { error = "Email and password are required." });

            var ok = await svc.RequestLoginAsync(email, password, ct);
            // Generic response — do not reveal whether the account exists / has a password.
            return ok
                ? Results.Ok(new { requiresOtp = true, email })
                : Results.Json(new { error = "Invalid email or password." }, statusCode: StatusCodes.Status401Unauthorized);
        });

        // Step 2: OTP → set the auth cookie (same as passkey login).
        group.MapPost("/verify-otp", async (
            JsonElement body, IPasswordAuthService svc, HttpContext http, CancellationToken ct) =>
        {
            var email = body.TryGetProperty("email", out var e) ? e.GetString() : null;
            var code = body.TryGetProperty("code", out var c) ? c.GetString() : null;
            if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(code))
                return Results.BadRequest(new { error = "Email and code are required." });

            var user = await svc.VerifyOtpAsync(email, code, ct);
            if (user is null)
                return Results.Json(new { error = "Invalid or expired code." }, statusCode: StatusCodes.Status401Unauthorized);

            var claims = AuthEndpoints.BuildClaims(user.UserId, user.DisplayName, user.Email, user.Phone);
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
            await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
            return Results.Ok(new { success = true, userId = user.UserId });
        });

        // First-time set + reset: token + new password.
        group.MapPost("/set", async (
            JsonElement body, IPasswordAuthService svc, CancellationToken ct) =>
        {
            var token = body.TryGetProperty("token", out var t) ? t.GetString() : null;
            var newPassword = body.TryGetProperty("newPassword", out var np) ? np.GetString() : null;
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(newPassword))
                return Results.BadRequest(new { error = "Token and a new password are required." });
            if (!PasswordPolicy.IsAcceptable(newPassword, out var pwError))
                return Results.BadRequest(new { error = pwError });

            var ok = await svc.SetPasswordAsync(token, newPassword, ct);
            return ok
                ? Results.Ok(new { success = true })
                : Results.BadRequest(new { error = "Invalid or expired link." });
        });

        // Forgot password — always 200 (no enumeration).
        group.MapPost("/forgot", async (
            JsonElement body, IPasswordAuthService svc, CancellationToken ct) =>
        {
            var email = body.TryGetProperty("email", out var e) ? e.GetString() : null;
            if (!string.IsNullOrWhiteSpace(email))
                await svc.RequestResetAsync(email, ct);
            return Results.Ok(new { success = true });
        });
    }
}
