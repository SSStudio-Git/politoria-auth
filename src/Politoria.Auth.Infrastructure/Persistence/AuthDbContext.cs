using Microsoft.EntityFrameworkCore;
using Politoria.Auth.Domain.Entities;

namespace Politoria.Auth.Infrastructure.Persistence;

public class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();
    // req/004 — email+password auth tokens.
    public DbSet<EmailOtpToken> EmailOtpTokens => Set<EmailOtpToken>();
    public DbSet<PasswordSetupToken> PasswordSetupTokens => Set<PasswordSetupToken>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.UseOpenIddict();

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasIndex(u => u.Email).IsUnique().HasFilter("email IS NOT NULL");
            entity.HasIndex(u => u.Phone).IsUnique().HasFilter("phone IS NOT NULL");
        });

        modelBuilder.Entity<PasskeyCredential>(entity =>
        {
            entity.HasIndex(p => p.CredentialId).IsUnique();

            entity.HasOne(p => p.User)
                .WithMany(u => u.Passkeys)
                .HasForeignKey(p => p.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<EmailOtpToken>(entity =>
        {
            entity.HasIndex(t => t.UserId);
            entity.HasIndex(t => t.Email);
        });

        modelBuilder.Entity<PasswordSetupToken>(entity =>
        {
            entity.HasIndex(t => t.Token).IsUnique();
            entity.HasIndex(t => t.UserId);
        });

        modelBuilder.ApplySnakeCaseNaming();
    }
}
