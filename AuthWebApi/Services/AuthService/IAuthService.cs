﻿using AuthWebApi.DTO;
using AuthWebApi.Model;

namespace AuthWebApi.Services.AuthService
{
    public interface IAuthService
    {
        Task<User> RegisterUser(UserDto request);
    }
}