using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Politoria.Auth.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddNicknameToUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "nickname",
                table: "users",
                type: "character varying(50)",
                maxLength: 50,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "nickname",
                table: "users");
        }
    }
}
