using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
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
    public class BasicAuthenticationOptions : AuthenticationSchemeOptions
    { }
    public class AuthorizationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        private readonly IAuthorizationManager authorizationManager;
        int tokenTimeout;
        public AuthorizationHandler(IOptionsMonitor<BasicAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IAuthorizationManager pAuthorizationManager,
            IConfiguration configuration) : base(options, logger, encoder, clock)
        {
            this.authorizationManager = pAuthorizationManager;
            tokenTimeout = Convert.ToInt16(configuration.GetSection("AppSettings").GetSection("TokenTimeout").Value);
        }
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            //throw new NotImplementedException();
            if (!Request.Headers.ContainsKey("Authorization"))
                return Task.FromResult(AuthenticateResult.Fail("Unauthorized"));

            string authorizationHeader = Request.Headers["Authorization"];
            if (string.IsNullOrEmpty(authorizationHeader))
                return Task.FromResult(AuthenticateResult.Fail("Unauthorize"));

            if (!authorizationHeader.StartsWith("bearer", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(AuthenticateResult.Fail("Unauthorize"));

            string token = authorizationHeader.Substring("bearer".Length).Trim();

            if (string.IsNullOrEmpty(token))
                return Task.FromResult(AuthenticateResult.Fail("Unauthorize"));

            try
            {
                return Task.FromResult(ValidateToken(token));
            }
            catch (Exception ex)
            {
                // Log 
                return Task.FromResult(AuthenticateResult.Fail("Unauthorize"));
            }
        }
        private AuthenticateResult ValidateToken(string token)
        {
            var validatedToken = authorizationManager.Tokens.FirstOrDefault(t => t.Key == token);
            if (validatedToken.Key == null)
            {
                return AuthenticateResult.Fail("Unauthorize");
            }

            var vItem = authorizationManager.Tokens.ToList().Find(x => x.Key == token);
            int vDiff = (int)(DateTime.Now - vItem.Value.Item3).TotalMinutes;
            if (vDiff > tokenTimeout)
            {
                authorizationManager.Tokens.Remove(token);
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
