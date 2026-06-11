namespace Politoria.Contracts.Communication;

/// <summary>
/// req/004 — local mirror of the platform <c>SendEmail</c> command. The namespace
/// + type name match <c>politoria-contracts</c> exactly, so MassTransit routes a
/// message published here to the SAME exchange that <c>Hrms.Communication</c>'s
/// <c>SendEmailConsumer</c> binds to (which now delivers via Resend). Defined
/// locally to keep the standalone auth service free of the contracts build context.
/// </summary>
public record SendEmail(string ToEmail, string Subject, string HtmlBody, string? PlainBody = null);
