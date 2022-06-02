using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace APIsSecures.Controllers
{
    [Route("wolf{version:apiVersion}/api/[controller]")]
    [ApiController]
    [AllowAnonymous]
    [ApiVersion("1.0")]
    [ApiVersion("2.0")]
    public class LoginController : ControllerBase
    {
        static APIsToken.IAuthorizationManager authorizationManager;

        public LoginController(APIsToken.IAuthorizationManager pAuthorizationManager)
        {
            authorizationManager = pAuthorizationManager;
        }
        /// <summary>
        /// login to get token before execute APIs
        /// </summary>
        /// <param name="user"></param>
        /// <param name="pwd"></param>
        /// <returns>return token</returns>
        [NonAction]
        [HttpGet]
        public IActionResult Get(string user, string pwd)
        {
            Models.TokenModel vModel = new Models.TokenModel();
            try
            {
                var vToken = authorizationManager.Authenticate(user, pwd);
                vModel.Token = vToken.ToUpper();
                return Ok(vModel);
            }
            catch (Exception exp)
            {
                return BadRequest(new Models.LoginModel());
            }
        }
        /// <summary>
        /// login to get token before execute APIs
        /// </summary>
        /// <param name="user"></param>
        /// <param name="pwd"></param>
        /// <param name="data"></param>
        /// <returns>return token</returns>
        [HttpPost]
        public IActionResult Post(Models.LoginModel data)
        {
            try
            {
                Models.TokenModel vModel = new Models.TokenModel();
                var vToken = authorizationManager.Authenticate(data.User, data.Pass);
                if (vToken != null)
                {
                    vModel.Token = vToken.ToUpper();
                    return Ok(vModel);
                }
                else
                {
                    return BadRequest(vModel);
                }
            }
            catch(Exception exp)
            {
                return BadRequest(new Models.TokenModel());
            }
        }
    }
}
