using DemoAuthJwt.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace DemoAuthJwt.Data {
	public class ApplicationDbContext : IdentityDbContext {
		public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

		public DbSet<Team> Teams { get; set; }
		public DbSet<RefreshToken> RefreshTokens { get; set; }
	}
}
