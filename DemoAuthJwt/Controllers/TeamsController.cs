using DemoAuthJwt.Data;
using DemoAuthJwt.Models;
using DemoAuthJwt.Models.DTOs;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace DemoAuthJwt.Controllers {
	[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
	[Route("api/[controller]")]
	[ApiController]
	[Authorize]
	public class TeamsController : ControllerBase {
		private readonly ApplicationDbContext _dbContext;

		public TeamsController(ApplicationDbContext dbContext) {
			_dbContext = dbContext;
		}

		[HttpGet("GetAll")]
		public async Task<IActionResult> GetAll() {
			try {
				var teams = await _dbContext.Teams.ToListAsync();
				return Ok(new ResponseDto<List<Team>>() {
					Data = teams,
					IsSuccess = true
				});
			} catch (Exception ex) {
				return BadRequest(new ResponseDto<Team>() {
					IsSuccess = false,
					Message = ex.Message
				});
			}
		}

		[HttpGet]
		[Route("GetTeamById/{id}")]
		public async Task<IActionResult> Get(int id) {
			try {
				var team = await _dbContext.Teams.FirstOrDefaultAsync(x => x.Id == id);
				return Ok(new ResponseDto<Team>() {
					Data = team,
					IsSuccess = true
				});
			} catch (Exception ex) {
				return BadRequest(new ResponseDto<Team>() {
					IsSuccess = false,
					Message = ex.Message
				});
			}
		}

		[HttpPost("CreateTeam")]
		public async Task<IActionResult> Create([FromBody] TeamRequestDto requestDto) {
			try {
				if(requestDto != null) {
					var newTeam = new Team {
						Name = requestDto.Name,
						Country = requestDto.Country,
						TeamPrinciple = requestDto.TeamPrinciple,
					};
					await _dbContext.AddAsync(newTeam);
					await _dbContext.SaveChangesAsync();
					return Ok(new ResponseDto<Team>() {
						IsSuccess = true,
						Data = newTeam
					});
				}
				return BadRequest(new ResponseDto<Team>() {
					IsSuccess = true,
					Message = "Invalid payload"
				});
			} catch (Exception ex) {
				return BadRequest(new ResponseDto<Team>() {
					IsSuccess = false,
					Message = ex.Message
				});
			}
		}

		[HttpPut]
		[Route("UpdateTeam/{id}")]
		public async Task<IActionResult> Update(int id, [FromBody] TeamRequestDto requestDto) {
			try {
				var teamFromDb = await _dbContext.Teams.FirstOrDefaultAsync(x => x.Id == id);
				if(teamFromDb != null) {
					teamFromDb.Name = requestDto.Name;
					teamFromDb.Country = requestDto.Country;
					teamFromDb.TeamPrinciple = requestDto.TeamPrinciple;
					_dbContext.Update(teamFromDb);
					await _dbContext.SaveChangesAsync();

					return Ok(new ResponseDto<Team>() {
						IsSuccess = true,
						Message = "Updated successful"
					});
				}
				return BadRequest(new ResponseDto<Team>() {
					IsSuccess = false,
					Message = "Not found"
				});
			} catch (Exception ex) {
				return BadRequest(new ResponseDto<Team>() {
					IsSuccess = false,
					Message = ex.Message
				});
			}
		}

		[HttpDelete]
		[Route("DeleteTeam/{id}")]
		public async Task<IActionResult> Delete(int id) {
			try {
				var teamToBeDelete = await _dbContext.Teams.FirstOrDefaultAsync(x => x.Id == id);
				if(teamToBeDelete != null) {
					_dbContext.Remove(teamToBeDelete);
					await _dbContext.SaveChangesAsync();
					return Ok(new ResponseDto<Team>() {
						IsSuccess = true,
						Message = "Deleted successful"
					});
				}
				return BadRequest(new ResponseDto<Team>() {
					IsSuccess = false,
					Message = "Not found"
				});
			} catch (Exception ex) {
				return BadRequest(new ResponseDto<Team>() {
					IsSuccess = false,
					Message = ex.Message
				});
			}
		}
	}
}
