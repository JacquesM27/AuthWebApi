using AuthWebApi.DTO;
using AuthWebApi.Model;
using AuthWebApi.Services.AuthService;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost]
        public async Task<ActionResult<User>> RegisterUser(UserDto request)
        {
            var response = await _authService.RegisterUser(request);
            return Ok(response);
        }

        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<User>> Login(UserDto request)
        {
            var response = await _authService.Login(request);
            if (response.Success)
            {
                return Ok(response);
            }
            return BadRequest(response.Message);
        }

        [HttpGet, Authorize(Roles = "Admin,User")]
        public ActionResult<string> Aloha()
        {
            return Ok("Aloha. You are authorized!");
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken(UserDto request)
        {
            var response = await _authService.RefreshToken();
            if (response.Success)
            {
                return Ok(response);
            }
            return BadRequest(response.Message);
        }

    }
}
