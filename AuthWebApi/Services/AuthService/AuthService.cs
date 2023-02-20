using AuthWebApi.Data;
using AuthWebApi.DTO;
using AuthWebApi.Model;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AuthWebApi.Services.AuthService
{
    public class AuthService : IAuthService
    {
        private readonly DataContext _dataContext;
        private readonly IConfiguration _configuration;

        public AuthService(DataContext dataContext, IConfiguration configuration)
        {
            _dataContext = dataContext;
            _configuration = configuration;
        }

        public async Task<AuthResponseDto> Login(UserDto request)
        {
            var user = await _dataContext.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user == null)
            {
                return new AuthResponseDto { Message = "User not found." };
            }
            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return new AuthResponseDto { Message = "Wrong password." };
            }

            string token = CreateToken(user);
            return new AuthResponseDto { Success = true, Token = token };
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

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512(passwordSalt);
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return computedHash.SequenceEqual(passwordHash);
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using var hmac = new HMACSHA512();
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new()
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
       
    }
}
