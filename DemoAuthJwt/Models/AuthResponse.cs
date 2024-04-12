namespace DemoAuthJwt.Models {
	public class AuthResponse {
		public string Token { get; set; }
		public string RefreshToken { get; set; }
		public bool IsSuccess { get; set; }
		public List<string> Errors { get; set; }
	}
}
