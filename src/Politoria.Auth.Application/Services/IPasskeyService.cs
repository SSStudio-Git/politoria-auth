using System.Text.Json;
using Politoria.Auth.Application.DTOs;

namespace Politoria.Auth.Application.Services;

public interface IPasskeyService
{
    /// <summary>
    /// Start passkey registration. When <paramref name="userId"/> is provided,
    /// the created User record will use that Guid (used for HRMS invite handoffs
    /// where the Identity already exists in hrms_identity with a known Id).
    /// When <paramref name="inviteEmail"/> is provided (invite handoffs), it is kept
    /// with the challenge so completion can re-check it against existing accounts.
    /// </summary>
    Task<object> BeginRegisterAsync(
        string displayName, Guid? userId = null, string? inviteEmail = null, CancellationToken ct = default);

    /// <summary>
    /// True when <paramref name="email"/> already belongs to a user whose id is not
    /// <paramref name="userId"/>. An invite for such an email must be refused with
    /// <see cref="InviteAccountGuard.ExistingAccountError"/>: never a second user.
    /// </summary>
    Task<bool> InviteEmailBelongsToOtherUserAsync(Guid userId, string? email, CancellationToken ct = default);

    Task<AuthResult> CompleteRegisterAsync(JsonElement request, CancellationToken ct = default);
    Task<object> BeginLoginAsync(CancellationToken ct = default);
    Task<AuthResult> CompleteLoginAsync(JsonElement request, CancellationToken ct = default);
}
