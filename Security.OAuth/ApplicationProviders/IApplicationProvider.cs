namespace Framework.Security.OAuth.ApplicationProviders
{
    using System;

    public interface IApplicationProvider
    {
        #region Methods

        string CreateToken(IApplication application, string userId);

        void DeleteUserToken(IApplication application, string userId, string token);

        void SaveUserToken(IApplication application, string userId, string token);

        bool ValidateApplication(string id, string secret, out IApplication application);

        bool ValidateUserRefreshToken(string token, IApplication application, out IUser user);

        #endregion Methods
    }
}