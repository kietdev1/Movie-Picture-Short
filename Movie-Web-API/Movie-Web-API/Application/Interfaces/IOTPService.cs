﻿
using Domain.Common;
using Domain.DTOs;
using Domain.Entities;

namespace Application.Interfaces
{
    public interface IOTPService
    {
        Task<bool> GetOTPAsync(OtpDTO otpDTO);
        Task<Response<string>> CreateOTPAsync(OtpDTO otpDTO);
        Task<bool> VerifyOTPAsync(OtpDTO otpDTO);
        Task<Response<string>> DeleteOTPAsync(string mailAddress);
    }
}
