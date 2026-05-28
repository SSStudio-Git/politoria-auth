namespace Politoria.Auth.Application.DTOs;

public record AuthResult(bool Success, Guid? UserId, string? Error);
