using System.Net;

namespace Politoria.Auth.Infrastructure.Services;

/// <summary>
/// Pieces of the auth emails' body. Hrms.Communication wraps every email in the
/// branded layout (logo, card, footer) when it sends it; these are the same
/// button / code / note markup as <c>Hrms.SharedKernel.Email.EmailLayout</c>,
/// copied because auth doesn't reference HRMS. Keep the two in step.
/// </summary>
internal static class AuthEmailMarkup
{
    const string Brick = "#B22222";
    const string Paper = "#F4EFE6";
    const string Ink = "#1F1A17";
    const string Muted = "#7A6F66";
    const string Rule = "#E6DED2";
    const string Font = "Rubik, 'Segoe UI', Tahoma, Arial, sans-serif";

    public static string P(string text) => $"<p>{Enc(text)}</p>";

    public static string Button(string text, string url) =>
        $"<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"margin:24px 0\"><tr>" +
        $"<td style=\"background:{Brick};border-radius:8px\">" +
        $"<a href=\"{Enc(url)}\" style=\"display:inline-block;padding:13px 30px;font-family:{Font};font-size:16px;font-weight:bold;color:#ffffff;text-decoration:none;border-radius:8px\">{Enc(text)}</a>" +
        "</td></tr></table>";

    public static string Code(string code) =>
        $"<div dir=\"ltr\" style=\"margin:24px 0;padding:18px 0;background:{Paper};border:1px solid {Rule};border-radius:10px;text-align:center;" +
        $"font-family:'SFMono-Regular',Consolas,'Courier New',monospace;font-size:34px;font-weight:bold;letter-spacing:10px;color:{Ink}\">{Enc(code)}</div>";

    public static string Note(string text) =>
        $"<p style=\"margin:16px 0 0;font-size:13px;line-height:1.8;color:{Muted}\">{Enc(text)}</p>";

    public static string FallbackLink(string url) =>
        $"<p style=\"margin:8px 0 0;font-size:12px;line-height:1.6;color:{Muted};word-break:break-all\">" +
        $"<a href=\"{Enc(url)}\" style=\"color:{Muted}\">{Enc(url)}</a></p>";

    static string Enc(string s) => WebUtility.HtmlEncode(s);
}
