using AuthWebApi.Data;
using AuthWebApi.DTO;
using AuthWebApi.Model;
using System.Security.Cryptography;

namespace AuthWebApi.Services.AuthService
{
    public class AuthService : IAuthService
    {
        private readonly DataContext _dataContext;

        public AuthService(DataContext dataContext)
        {
            _dataContext = dataContext;
        }

        public async Task<User> RegisterUser(UserDto request)
        {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            User user = new() 
            { 
                Username = request.Username,
                PasswordHash= passwordHash,
                PasswordSalt= passwordSalt
            };

            _dataContext.Users.Add(user);
            await _dataContext.SaveChangesAsync();
            return user;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512();
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }
    }
}
