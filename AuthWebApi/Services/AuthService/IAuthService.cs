using AuthWebApi.DTO;
using AuthWebApi.Model;

namespace AuthWebApi.Services.AuthService
{
    public interface IAuthService
    {
        Task<User> RegisterUser(UserDto request);
        Task<AuthResponseDto> Login(UserDto request);
        Task<AuthResponseDto> RefreshToken();
    }
}
