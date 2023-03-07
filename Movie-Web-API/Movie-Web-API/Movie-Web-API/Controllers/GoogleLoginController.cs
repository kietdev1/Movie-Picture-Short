using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Application.Interfaces;
using Domain.Common;
using Domain.DTOs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Movie_Web_API.Controllers
{
    [ApiController]
    public class GoogleLoginController : ControllerBase
    {
        private readonly IRecoveryTokenService _recoveryTokenService;
        private readonly IUserService _userService;
        private readonly string m_tokenKeyName = "refreshtoken";

        public GoogleLoginController(IRecoveryTokenService recoveryTokenService, IUserService userService)
        {
            _recoveryTokenService = recoveryTokenService;
            _userService = userService;
        }

        [HttpGet("google-login")]
        [AllowAnonymous]
        public IActionResult GoogleLogin()
        {
            var properties = new AuthenticationProperties {};
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("signin-google")]
        [AllowAnonymous]
        public async Task<IActionResult> GoogleResponse()
        {
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (result == null)
            {
                return Redirect("google-login");
            }

            var claims = result.Principal.Identities
                    .FirstOrDefault()?.Claims.Select(claim => new
                    {
                        claim.Issuer,
                        claim.OriginalIssuer,
                        claim.Type,
                        claim.Value
                    });

            string fname = "";
            string lname = "";
            string email = "";
            //var jwt = "";
            if (claims.Count() > 3)
            {
                fname = claims.ToList()[2].Value.ToString();
                lname = claims.ToList()[3].Value.ToString();
                email = claims.ToList()[4].Value.ToString();
            }

            var user = _userService.CheckUserExist(email);

            Response<string> jwt = null;

            if (user.Result == false)
            {
                jwt = _recoveryTokenService.AuthenticateG(email, GetclientIpv4Address()).Result;
            }
            else
            {
                UserDTO userDTO = new UserDTO()
                {
                    Id = Guid.Parse(user.Id.ToString()),
                    Email = email,
                    FirstName = fname,
                    LastName = lname,
                    UserName = email,
                    Role = Role.Guest
                };
                await _userService.Register(userDTO);

                jwt = _recoveryTokenService.AuthenticateG(email, GetclientIpv4Address()).Result;
            }
            return Redirect(@"http://localhost:4200?token=" + jwt + "&id=" + user.Id);
        }

        private string GetclientIpv4Address()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
            {
                return Request.Headers["X-Forwarded-for"];
            }
            else
            {
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
            }
        }
    }
}