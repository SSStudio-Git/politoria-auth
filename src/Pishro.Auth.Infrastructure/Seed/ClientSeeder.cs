using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace Pishro.Auth.Infrastructure.Seed;

public class ClientSeeder(
    IOpenIddictApplicationManager manager,
    IOpenIddictScopeManager scopes,
    IConfiguration configuration,
    ILogger<ClientSeeder> logger)
{
    /// <summary>
    /// Fine-grained admin scope naming convention is
    /// <c>pishro-auth.admin.&lt;domain&gt;.&lt;action&gt;</c>. New admin endpoints
    /// must add their own slug here rather than reusing a coarse umbrella.
    /// </summary>
    public const string AdminUsersDeleteScope = "pishro-auth.admin.users.delete";

    public async Task SeedAsync(CancellationToken ct = default)
    {
        // Custom scopes used by the HRMS client — must exist before a client
        // can request them, otherwise OpenIddict rejects the authorize call
        // with ID2051 ("client not allowed to use the specified scope").
        if (await scopes.FindByNameAsync("roles", ct) is null)
        {
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "roles",
                DisplayName = "Roles",
                Description = "HRMS roles and permissions"
            }, ct);
        }

        if (await scopes.FindByNameAsync("vetting_status", ct) is null)
        {
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = "vetting_status",
                DisplayName = "Vetting status",
                Description = "HRMS vetting lifecycle state"
            }, ct);
        }

        if (await scopes.FindByNameAsync(AdminUsersDeleteScope, ct) is null)
        {
            await scopes.CreateAsync(new OpenIddictScopeDescriptor
            {
                Name = AdminUsersDeleteScope,
                DisplayName = "Admin: delete users",
                Description = "Permission to hard-delete user accounts via /api/admin/users/{id}.",
            }, ct);
        }

        // Portal client
        // Portal client — rewritten on every startup (same pattern as hrms
        // below) so PostLogoutRedirectUris and permission edits actually
        // take effect rather than getting stuck on the seed-time set.
        var portalDescriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "portal",
            DisplayName = "Civic Compass Portal",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            RedirectUris =
            {
                new Uri("https://portal.pishro.party/api/auth/callback"),
                new Uri("http://localhost:3100/api/auth/callback"),
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://portal.pishro.party/"),
                new Uri("http://localhost:3100/"),
            },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Phone,
            },
            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
            },
        };
        var existingPortal = await manager.FindByClientIdAsync("portal", ct);
        if (existingPortal is null)
            await manager.CreateAsync(portalDescriptor, ct);
        else
            await manager.UpdateAsync(existingPortal, portalDescriptor, ct);

        // HRMS client (includes roles + vetting_status scopes for authorization).
        // The client descriptor is rewritten on every startup so permission/scope
        // edits in source actually take effect — the original FindByClientIdAsync
        // guard left old clients stuck with the seed-time permission set.
        var hrmsDescriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = "hrms",
            DisplayName = "HRMS ERP",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            RedirectUris =
            {
                new Uri("https://erp.pishro.party/api/auth/callback"),
                new Uri("http://localhost:3000/api/auth/callback")
            },
            PostLogoutRedirectUris =
            {
                new Uri("https://erp.pishro.party/"),
                new Uri("http://localhost:3000/")
            },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Phone,
                OpenIddictConstants.Permissions.Prefixes.Scope + "roles",
                OpenIddictConstants.Permissions.Prefixes.Scope + "vetting_status"
            },
            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
            }
        };

        var existingHrms = await manager.FindByClientIdAsync("hrms", ct);
        if (existingHrms is null)
            await manager.CreateAsync(hrmsDescriptor, ct);
        else
            await manager.UpdateAsync(existingHrms, hrmsDescriptor, ct);

        // hrms-admin — confidential service client used by Hrms.Identity to call
        // /api/admin/* via the OAuth2 client_credentials grant. Replaces the
        // legacy X-Admin-Key shared secret. Secret is generated on first boot;
        // subsequent boots leave the existing client alone (rotating means
        // deleting the row and restarting). Plaintext is logged ONCE here —
        // the operator must copy it into HRMS env on the prod cutover.
        await SeedHrmsAdminClientAsync(ct);
    }

    private async Task SeedHrmsAdminClientAsync(CancellationToken ct)
    {
        const string clientId = "hrms-admin";
        var existing = await manager.FindByClientIdAsync(clientId, ct);
        if (existing is not null)
        {
            logger.LogInformation(
                "OIDC client '{ClientId}' already exists; secret unchanged. " +
                "To rotate, delete the openiddict_applications row and restart.",
                clientId);
            return;
        }

        // Pre-seed path for dev / scripted environments: if the operator has
        // pre-set this in config (env var: OIDC_HRMS_ADMIN_BOOTSTRAP_SECRET or
        // appsettings Oidc:HrmsAdminBootstrapSecret), use it. Otherwise generate
        // a fresh 32-byte secret. Either way, the value is hashed by OpenIddict
        // before persistence — we never see it again after this boot.
        var bootstrap = configuration["Oidc:HrmsAdminBootstrapSecret"];
        var generated = !string.IsNullOrWhiteSpace(bootstrap);
        var secret = generated ? bootstrap! : GenerateSecret();

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = "HRMS Identity (admin S2S)",
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ClientSecret = secret,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.Prefixes.Scope + AdminUsersDeleteScope,
            },
        };

        await manager.CreateAsync(descriptor, ct);

        // ONE-TIME logging of plaintext secret. Wrapped in obvious markers so
        // the operator can grep it out of the boot logs and paste it into the
        // HRMS environment file. After this single boot, OpenIddict has only
        // the hashed value — there is no recovery path.
        var source = generated ? "from Oidc:HrmsAdminBootstrapSecret config" : "freshly generated";
        logger.LogWarning(
            "═══════════════════════════════════════════════════════════════════\n" +
            "ONE-TIME OIDC CLIENT SECRET — STORE THIS NOW\n" +
            "  client_id     : {ClientId}\n" +
            "  client_secret : {Secret}\n" +
            "  source        : {Source}\n" +
            "Set this on HRMS as PishroAuth__AdminClientSecret. The plaintext\n" +
            "is hashed in the IdP DB; this is the only time it will appear.\n" +
            "═══════════════════════════════════════════════════════════════════",
            clientId, secret, source);
    }

    private static string GenerateSecret()
    {
        // 32 bytes of entropy, base64url-encoded — 43 ASCII chars without padding.
        Span<byte> buffer = stackalloc byte[32];
        RandomNumberGenerator.Fill(buffer);
        return Convert.ToBase64String(buffer)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
