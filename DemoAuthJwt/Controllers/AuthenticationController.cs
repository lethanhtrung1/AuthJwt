using DemoAuthJwt.Data;
using DemoAuthJwt.Models;
using DemoAuthJwt.Models.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace DemoAuthJwt.Controllers {
	[Route("api/[controller]")] // api/authentication
	[ApiController]
	public class AuthenticationController : ControllerBase {
		private readonly UserManager<IdentityUser> _userManager;
		private readonly IConfiguration _configuration;
		private readonly TokenValidationParameters _tokenValidationParameters;
		private readonly ApplicationDbContext _dbContext;

		public AuthenticationController(UserManager<IdentityUser> userManager, IConfiguration configuration,
			ApplicationDbContext dbContext, TokenValidationParameters tokenValidationParameters) {
			_userManager = userManager;
			_configuration = configuration;
			_dbContext = dbContext;
			_tokenValidationParameters = tokenValidationParameters;
		}

		[HttpPost]
		[Route("Register")]
		public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto) {
			try {
				// Validate th iscoming request
				if (ModelState.IsValid) {
					// Check email already exist
					var userExist = await _userManager.FindByEmailAsync(requestDto.Email);
					if (userExist != null) {
						return BadRequest(new AuthResponse() {
							IsSuccess = false,
							Errors = new List<string>() { "Email already exist" }
						});
					}
					// creat a user
					var newUser = new IdentityUser() {
						Email = requestDto.Email,
						UserName = requestDto.Email,
					};
					var isCreated = await _userManager.CreateAsync(newUser, requestDto.Password);
					if (isCreated.Succeeded) {
						// Generate the Token ...
						var jwtToken = await GenerateJwtToken(newUser);

						return Ok(jwtToken);
					}
					return BadRequest(new AuthResponse() {
						IsSuccess = false,
						Errors = new List<string>() { "Server error" }
					});
				}

				return BadRequest(new AuthResponse() {
					IsSuccess = false,
					Errors = new List<string>() { "Invalid payload" }
				});
			} catch (Exception ex) {
				return BadRequest(new AuthResponse() {
					IsSuccess = false,
					Errors = new List<string>() { ex.Message }
				});
			}
		}


		[HttpPost]
		[Route("Login")]
		public async Task<IActionResult> Login([FromBody] UserLoginRequestDto requestDto) {
			try {
				if (ModelState.IsValid) {
					var existingUser = await _userManager.FindByEmailAsync(requestDto.Email);
					if (existingUser == null) {
						return BadRequest(new AuthResponse() {
							IsSuccess = false,
							Errors = new List<string>() { "Invalid payload" }
						});
					}
					var isCorrect = await _userManager.CheckPasswordAsync(existingUser, requestDto.Password);
					if (!isCorrect) {
						return BadRequest(new AuthResponse() {
							IsSuccess = false,
							Errors = new List<string>() { "Invalid payload" }
						});
					}
					var jwtToken = await GenerateJwtToken(existingUser);

					return Ok(jwtToken);
				}

				return BadRequest(new AuthResponse() {
					IsSuccess = false,
					Errors = new List<string>() { "Invalid payload" }
				});
			} catch (Exception ex) {
				return BadRequest(new AuthResponse() {
					IsSuccess = false,
					Errors = new List<string>() { ex.Message }
				});
			}
		}

		[HttpPost]
		[Route("RefreshToken")]
		public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest) {
			try {
				if (ModelState.IsValid) {
					var result = await VerifyAndGenerateToken(tokenRequest);

					if (result == null) {
						return BadRequest(new AuthResponse() {
							IsSuccess = false,
							Errors = new List<string> { "Invalid tokens" }
						});
					}
					return Ok(result);
				}
				return BadRequest(new AuthResponse() {
					IsSuccess = false,
					Errors = new List<string> { "Invalid payload" }
				});
			} catch (Exception) {

				throw;
			}
		}


		private async Task<AuthResponse> VerifyAndGenerateToken(TokenRequest tokenRequest) {
			var jwtTokenHandler = new JwtSecurityTokenHandler();

			try {
				_tokenValidationParameters.ValidateLifetime = false; // for testing - it should be true

				var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);
				if (validatedToken is JwtSecurityToken jwtSecurityToken) {
					var resutl = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
					if (resutl == false) {
						return null;
					}
				}

				// validate expiry time of the token
				var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
				// Convert long to DateTime
				var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);
				if (expiryDate > DateTime.Now) {
					return new AuthResponse() {
						IsSuccess = false,
						Errors = new List<string> { "Expired token" }
					};
				}

				// Check token in db
				var storedToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);
				if(storedToken == null || storedToken.IsUsed || storedToken.IsRevoked) {
					return new AuthResponse() {
						IsSuccess = false,
						Errors = new List<string> { "Invalid token" }
					};
				}
				var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
				if(storedToken.JwtId != jti) {
					return new AuthResponse() {
						IsSuccess = false,
						Errors = new List<string> { "Invalid token" }
					};
				}
				if(storedToken.ExpiryDate < DateTime.UtcNow) {
					return new AuthResponse() {
						IsSuccess = false,
						Errors = new List<string> { "Expired token" }
					};
				}

				storedToken.IsUsed = true;
				_dbContext.RefreshTokens.Update(storedToken);
				await _dbContext.SaveChangesAsync();

				var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
				// call func generate new jwt token
				return await GenerateJwtToken(dbUser);

			} catch (Exception ex) {
				Console.WriteLine(ex.Message);
				return new AuthResponse() {
					IsSuccess = false,
					Errors = new List<string> { "Server error" }
				};
			}
		}


		private DateTime UnixTimeStampToDateTime(long unixTimeStamp) {
			var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
			dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();
			return dateTimeVal;
		}


		private async Task<AuthResponse> GenerateJwtToken(IdentityUser user) {
			var jwtTokenHandler = new JwtSecurityTokenHandler();

			var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value); // byte[]

			// Token descriptor
			var tokenDescriptor = new SecurityTokenDescriptor() {
				Subject = new ClaimsIdentity(new[] {
					new Claim("Id", user.Id),
					new Claim(JwtRegisteredClaimNames.Sub, user.Email),
					new Claim(JwtRegisteredClaimNames.Email, user.Email),
					new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
					new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString()),
				}),
				// how long will this token lives
				// Expires = DateTime.Now.AddHours(1),
				Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value)),
				SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
			};
			var token = jwtTokenHandler.CreateToken(tokenDescriptor);
			var jwtToken = jwtTokenHandler.WriteToken(token);

			// Refresh Token
			var refreshToken = new RefreshToken() {
				JwtId = token.Id,
				Token = RandomStringGeneration(), // Generate a refresh token
				AddedDate = DateTime.UtcNow,
				ExpiryDate = DateTime.UtcNow.AddMonths(6),
				IsUsed = false,
				IsRevoked = false,
				UserId = user.Id,
			};

			await _dbContext.RefreshTokens.AddAsync(refreshToken);
			await _dbContext.SaveChangesAsync();

			return new AuthResponse() {
				Token = jwtToken,
				RefreshToken = refreshToken.Token,
				IsSuccess = true,
			};
		}

		private string RandomStringGeneration() {
			//var random = new Random();
			//var chars = "ABCDEFGHJKLMNOPQRSTUVWXYZ1234567890abcdefghjklmnoprstuvwxyz_@";
			//return new string(Enumerable.Repeat(chars, length).Select(x => x[random.Next(x.Length)]).ToArray());

			var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
			// ensure token is unique by checking against db
			var tokenIsUnique = !_dbContext.RefreshTokens.Any(x => x.Token == token);
			if (!tokenIsUnique) {
				return RandomStringGeneration();
			}
			return token;
		}
	}
}
