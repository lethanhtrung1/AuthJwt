using System.ComponentModel.DataAnnotations;

namespace DemoAuthJwt.Models.DTOs {
	public class UserLoginRequestDto {
		[Required]
		public string Email { get; set; }
		[Required]
		public string Password { get; set; }
	}
}
