using System.Linq;

namespace Politoria.Auth.Application.Services;

/// <summary>
/// req/004 C3 — shared password-strength rule for set-password + self-signup.
/// Deliberately moderate (min length + a letter + a digit) so it's strong enough
/// to resist trivial guessing without frustrating the diaspora membership.
/// </summary>
public static class PasswordPolicy
{
    public const int MinLength = 8;

    public static bool IsAcceptable(string? password, out string error)
    {
        if (string.IsNullOrEmpty(password) || password.Length < MinLength)
        {
            error = $"Password must be at least {MinLength} characters.";
            return false;
        }
        if (!password.Any(char.IsLetter))
        {
            error = "Password must contain at least one letter.";
            return false;
        }
        if (!password.Any(char.IsDigit))
        {
            error = "Password must contain at least one number.";
            return false;
        }
        error = "";
        return true;
    }
}
