using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Politoria.Auth.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPasswordAuth : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "password_hash",
                table: "users",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "email_otp_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    email = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    code = table.Column<string>(type: "character varying(12)", maxLength: 12, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    attempts = table.Column<int>(type: "integer", nullable: false),
                    is_used = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_email_otp_tokens", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "password_setup_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    token = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    is_used = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_password_setup_tokens", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_email_otp_tokens_email",
                table: "email_otp_tokens",
                column: "email");

            migrationBuilder.CreateIndex(
                name: "ix_email_otp_tokens_user_id",
                table: "email_otp_tokens",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "ix_password_setup_tokens_token",
                table: "password_setup_tokens",
                column: "token",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_password_setup_tokens_user_id",
                table: "password_setup_tokens",
                column: "user_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "email_otp_tokens");

            migrationBuilder.DropTable(
                name: "password_setup_tokens");

            migrationBuilder.DropColumn(
                name: "password_hash",
                table: "users");
        }
    }
}
