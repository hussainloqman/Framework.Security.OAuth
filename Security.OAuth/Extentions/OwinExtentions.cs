namespace Framework.Security.OAuth
{
    using System;

    using Autofac;
    using Autofac.Core.Lifetime;

    using Microsoft.Owin;
    using Microsoft.Owin.Security.Infrastructure;
    using Microsoft.Owin.Security.OAuth;

    using global::Owin;
    using ApplicationProviders;
    using UserValidators;

    public static class OAuthAuthorizationServerExtention
    {
        #region Methods

        public static IAppBuilder UseAuthorizationServer(this IAppBuilder app, ILifetimeScope dependencyResolver, double expirationMinutes = 20, string tokenPath = "/token")
        {
            app.Use((ctx, next) =>
            {
                var scope = dependencyResolver.BeginLifetimeScope(MatchingScopeLifetimeTags.RequestLifetimeScopeTag);
                ctx.Set("IApplicationProvider", scope.Resolve<IApplicationProvider>());
                ctx.Set("UserValidatorFactory", scope.Resolve<UserValidatorFactory>());
                return next();
            });
            OAuthAuthorizationServerOptions options = new OAuthAuthorizationServerOptions()
            {
                TokenEndpointPath = new PathString(tokenPath),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(expirationMinutes),
                Provider = dependencyResolver.Resolve<OAuthAuthorizationServerProvider>(),
                RefreshTokenProvider = dependencyResolver.Resolve<IAuthenticationTokenProvider>(),
                AllowInsecureHttp = true
            };
            app.UseOAuthAuthorizationServer(options);
            return app;
        }

        #endregion Methods
    }
}