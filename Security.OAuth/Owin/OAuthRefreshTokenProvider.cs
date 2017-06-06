namespace Framework.Security.OAuth.Owin
{
    using System;
    using System.Security.Claims;
    using System.Threading.Tasks;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;
    using ApplicationProviders;

    public class OAuthRefreshTokenProvider : IAuthenticationTokenProvider
    {
        #region Constructors

        public OAuthRefreshTokenProvider()
        {
        }

        #endregion Constructors

        #region Methods

        public void Create(AuthenticationTokenCreateContext context)
        {
            throw new NotImplementedException();
        }

        public Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            var applicationProvider = context.OwinContext.Get<IApplicationProvider>("IApplicationProvider");
            var application = context.OwinContext.Get<IApplication>("oh:application");
            if (application == null)
                return Task.FromResult<object>(null);
            //--------------------------------------------------------------------------------------------------------------------
            var userId = context.Ticket.Identity.FindFirst("Id").Value;
            var refreshToken = applicationProvider.CreateToken(application, userId);

            context.Ticket.Properties.IssuedUtc = DateTime.UtcNow;
            context.Ticket.Properties.ExpiresUtc = DateTime.UtcNow.AddMinutes(Convert.ToDouble(application.RefreshTokenTimeout));
            context.SetToken(refreshToken);

            applicationProvider.SaveUserToken(application, userId, refreshToken);
            return Task.FromResult<object>(null);
        }

        public void Receive(AuthenticationTokenReceiveContext context)
        {
            throw new NotImplementedException();
        }

        public Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            var applicationProvider = context.OwinContext.Get<IApplicationProvider>("IApplicationProvider");
            var application = context.OwinContext.Get<IApplication>("oh:application");
            //--------------------------------------------------------------------------
            IUser user;
            if (applicationProvider.ValidateUserRefreshToken(context.Token, application, out user))
            {
                ClaimsIdentity identity = new ClaimsIdentity("bearer");
                AuthenticationProperties props = null;
                if (user != null)
                {
                    identity.AddClaim(new Claim(identity.NameClaimType, user.Username));
                    identity.AddClaim(new Claim("Id", user.Id));
                    foreach (var role in user.Roles)
                        identity.AddClaim(new Claim(identity.RoleClaimType, role));
                    foreach (var extra in user.AdditionalTokenParameters)
                        identity.AddClaim(new Claim(extra.Key, extra.Value));
                    props = new AuthenticationProperties(user.AdditionalResponseParameters);
                }
                var ticket = new AuthenticationTicket(identity, props);
                ticket.Properties.IssuedUtc = user.TokenIssueDate;
                ticket.Properties.ExpiresUtc = user.TokenIssueDate.AddMinutes(Convert.ToDouble(application.RefreshTokenTimeout));
                context.SetTicket(ticket);
                applicationProvider.DeleteUserToken(application, user.Id, context.Token);
            }
            return Task.FromResult<object>(null);
        }

        #endregion Methods
    }
}