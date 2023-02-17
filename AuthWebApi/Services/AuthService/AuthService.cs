using AuthWebApi.DTO;
using AuthWebApi.Model;

namespace AuthWebApi.Services.AuthService
{
    public class AuthService : IAuthService
    {
        public async Task<User> RegisterUser(UserDto request)
        {
            User user = new() { Username = request.Username };
            return user;
        }
    }
}
