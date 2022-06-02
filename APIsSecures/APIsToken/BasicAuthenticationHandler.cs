using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace APIsSecures.APIsToken
{
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IAuthorizationManager authorizationManager;
        int tokenTimeout;
        Models.AuthErrorModel authErrorModel = new Models.AuthErrorModel();
        public BasicAuthenticationHandler(IOptionsMonitor<BasicAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IAuthorizationManager pAuthorizationManager,
            Microsoft.Extensions.Configuration.IConfiguration configuration) : base(options, logger, encoder, clock)
        {
            this.authorizationManager = pAuthorizationManager;
            tokenTimeout = Convert.ToInt16(configuration.GetSection("AppSettings").GetSection("TokenTimeout").Value);
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            bool isAuthen = false;
            string authorizationHeader = "";
            string token = "";
            authErrorModel = new Models.AuthErrorModel();
            //throw new NotImplementedException();
            //request from another
            if (Request.Headers.ContainsKey("attn") == true)
            {
                isAuthen = true;
                token = Request.Headers["attn"];
            }
            //request from web ui(swagger) 
            if (Request.Headers.ContainsKey("Authorization") == true)
            {
                isAuthen = true;
                token = Request.Headers["Authorization"];
            }
            if(isAuthen == false)
            {
                authErrorModel.ErrMsg = "token invalid";
                return AuthenticateResult.Fail("Unauthorized");
            }

            if (string.IsNullOrEmpty(token))
            {
                authErrorModel.ErrMsg = "token invalid";
                return AuthenticateResult.Fail("Unauthorize");
            }

            //if (!authorizationHeader.StartsWith("bearer", StringComparison.OrdinalIgnoreCase))
            //    return Task.FromResult(AuthenticateResult.Fail("Unauthorize"));

            //string token = authorizationHeader;

            if (string.IsNullOrEmpty(token))
            {
                authErrorModel.ErrMsg = "token invalid";
                return AuthenticateResult.Fail("Unauthorize");
            }
            try
            {
                return ValidateToken(token);
            }
            catch (Exception ex)
            {
                // Log 
                return AuthenticateResult.Fail("Unauthorize");
            }
        }
        //protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        //{
        //    Response.StatusCode = 401;

        //    if (authErrorModel.ErrMsg != null)
        //    {
        //        Response.HttpContext.Features.Get<IHttpResponseFeature>().ReasonPhrase = failReason;
        //    }

        //    return Task.CompletedTask;
        //}
        private AuthenticateResult ValidateToken(string token)
        {
            var validatedToken = authorizationManager.Tokens.FirstOrDefault(t => t.Key == token);
            if (validatedToken.Key == null)
            {
                authErrorModel.ErrMsg = "token invalid";
                return AuthenticateResult.Fail("Unauthorize");
            }

            var vItem = authorizationManager.Tokens.ToList().Find(x => x.Key == token);
            int vDiff = (int)(DateTime.Now - validatedToken.Value.Item3).TotalMinutes;
            if (vDiff > tokenTimeout && tokenTimeout > -1)
            {
                authorizationManager.Tokens.Remove(token);
                authErrorModel.ErrMsg = "token expired";
                return AuthenticateResult.Fail("Unauthorize");
            }

            //for (int i = 0; i < authorizationManager.Tokens.Count; i++)
            //{
            //    var vItem = authorizationManager.Tokens.ElementAtOrDefault(i);
            //    int vDiff = (int)(DateTime.Now - vItem.Value.Item3).TotalMinutes;
            //    if (vDiff > tokenTimeout)
            //        authorizationManager.Tokens.Remove(vItem.Key);
            //}
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, validatedToken.Value.Item1),
                new Claim(ClaimTypes.Role, validatedToken.Value.Item2)
            };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new GenericPrincipal(identity, new[] { validatedToken.Value.Item2 });
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
    }
}
