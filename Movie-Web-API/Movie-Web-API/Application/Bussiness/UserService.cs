﻿using Application.Interfaces;
using Application.IRepositories;
using Domain.Common;
using Domain.DTOs;
using Domain.Entities;
using System.Text;

namespace Application.Bussiness
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;
        public UserService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }
        public async Task<UserDTO?> GetUser(Guid id)
        {
            return await _userRepository.GetDetailUserAsync(id);
        }

        public async Task<Response<Guid>> Register(UserDTO userDTO)
        {
            string encodedStr = Convert.ToBase64String(Encoding.UTF8.GetBytes(userDTO.Password));
            userDTO.Password = encodedStr;
            User user = new User(userDTO);
            await _userRepository.RegisterUserAsync(user);
            return Response<Guid>.Success(user.Id);
        }

        public async Task<bool> CheckUserExist(string email)
        {
            var user = await _userRepository.GetUserByEmailAsync(email);
            if (user != null)
                return true;
            return false;
        }
    }
}
