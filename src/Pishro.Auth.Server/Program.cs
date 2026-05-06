using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Pishro.Auth.Application.Services;
using Pishro.Auth.Infrastructure.Persistence;
using Pishro.Auth.Infrastructure.Seed;
using Pishro.Auth.Infrastructure.Services;
using Pishro.Auth.Server.Endpoints;

var builder = WebApplication.CreateBuilder(args);

// EF Core
builder.Services.AddDbContext<AuthDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("AuthDb"));
    options.UseOpenIddict();
});

// OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore().UseDbContext<AuthDbContext>();
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token")
               .SetUserInfoEndpointUris("/connect/userinfo")
               .SetEndSessionEndpointUris("/connect/logout");

        options.AllowAuthorizationCodeFlow()
               .RequireProofKeyForCodeExchange();

        // Service-to-service: HRMS Identity calls /api/admin/users/{id} with a
        // bearer token instead of the legacy X-Admin-Key header. The hrms-admin
        // confidential client uses this grant; requested scope is one of the
        // fine-grained pishro-auth.admin.* slugs (today only users.delete).
        options.AllowClientCredentialsFlow();

        options.RegisterScopes(
            "openid", "profile", "email", "phone", "roles", "vetting_status",
            "pishro-auth.admin.users.delete");

        // Dev signing credentials (replace with proper certs in production)
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // OpenIddict encrypts access tokens by default (JWE). Resource
        // servers (HRMS gateway, etc.) only do signature validation
        // against the JWKS — they can't decrypt JWE. Switch tokens to
        // unencrypted signed JWTs so any service can validate them.
        // Reference tokens for the introspection endpoint stay
        // encrypted; only browser-bound access tokens are affected.
        options.DisableAccessTokenEncryption();

        // Default access-token lifetime is 20 minutes — too short for an
        // active backoffice session; users hit silent 401s mid-flow.
        // 8 hours covers a working day. Refresh-token rotation is the
        // longer-term answer; for now, longer access tokens unblock the
        // immediate UX without weakening signature trust.
        options.SetAccessTokenLifetime(TimeSpan.FromHours(8));
        options.SetIdentityTokenLifetime(TimeSpan.FromHours(8));

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login.html";
    });

builder.Services.AddDistributedMemoryCache();
builder.Services.AddFido2(options =>
{
    options.ServerDomain = builder.Configuration["Fido2:ServerDomain"] ?? "localhost";
    options.ServerName = "Pishro Auth";
    options.Origins = new HashSet<string>(
        builder.Configuration.GetSection("Fido2:Origins").Get<string[]>() ?? ["http://localhost:5300"]);
});

builder.Services.AddAuthorization();

builder.Services.AddScoped<IPasskeyService, PasskeyService>();
builder.Services.AddScoped<IClaimsEnrichmentService, ClaimsEnrichmentService>();
builder.Services.AddScoped<IInviteHandoffService, InviteHandoffService>();
builder.Services.AddHttpClient("hrms-internal");
builder.Services.AddScoped<ClientSeeder>();

var app = builder.Build();

// Auto-migrate + seed
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await db.Database.MigrateAsync();
    var seeder = scope.ServiceProvider.GetRequiredService<ClientSeeder>();
    await seeder.SeedAsync();
}

// Trust reverse proxy: treat X-Forwarded-Proto as the real scheme
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Headers.TryGetValue("X-Forwarded-Proto", out var proto))
        ctx.Request.Scheme = proto.ToString();
    await next();
});

// Handle `prompt=register` before OpenIddict validates it (ID2032 "prompt not
// supported"). If the user is already signed in, the authorize flow continues
// normally after we strip the prompt. Otherwise we short-circuit to the
// registration page with the full authorize URL as returnUrl so it completes
// the code flow after registration.
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(ctx.Request.Query["prompt"], "register", StringComparison.OrdinalIgnoreCase))
    {
        var cookieResult = await ctx.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!cookieResult.Succeeded)
        {
            // Build returnUrl = same authorize URL minus the unsupported prompt.
            var rebuilt = new List<string>();
            foreach (var kv in ctx.Request.Query)
            {
                if (string.Equals(kv.Key, "prompt", StringComparison.OrdinalIgnoreCase)) continue;
                foreach (var v in kv.Value)
                    rebuilt.Add($"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(v ?? string.Empty)}");
            }
            var returnUrl = "/connect/authorize?" + string.Join("&", rebuilt);
            ctx.Response.Redirect($"/register.html?returnUrl={Uri.EscapeDataString(returnUrl)}");
            return;
        }

        // Already signed in: drop the prompt and let OpenIddict proceed.
        var filtered = ctx.Request.Query
            .Where(kv => !string.Equals(kv.Key, "prompt", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(kv => kv.Key, kv => kv.Value);
        ctx.Request.Query = new QueryCollection(filtered);
        ctx.Request.QueryString = QueryString.Create(
            filtered.SelectMany(kv => kv.Value.Select(v =>
                new KeyValuePair<string, string?>(kv.Key, v))));
    }
    await next();
});

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

// Map endpoints
app.MapAuthEndpoints();
app.MapConnectEndpoints();
app.MapAdminEndpoints();

app.MapGet("/health", () => Results.Ok(new { status = "healthy", service = "pishro-auth" }));

app.Run();
