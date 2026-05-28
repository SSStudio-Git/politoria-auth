using System.Text.Json;
using Politoria.Auth.Application.DTOs;

namespace Politoria.Auth.Application.Services;

public interface IPasskeyService
{
    /// <summary>
    /// Start passkey registration. When <paramref name="userId"/> is provided,
    /// the created User record will use that Guid (used for HRMS invite handoffs
    /// where the Identity already exists in hrms_identity with a known Id).
    /// </summary>
    Task<object> BeginRegisterAsync(string displayName, Guid? userId = null, CancellationToken ct = default);
    Task<AuthResult> CompleteRegisterAsync(JsonElement request, CancellationToken ct = default);
    Task<object> BeginLoginAsync(CancellationToken ct = default);
    Task<AuthResult> CompleteLoginAsync(JsonElement request, CancellationToken ct = default);
}
