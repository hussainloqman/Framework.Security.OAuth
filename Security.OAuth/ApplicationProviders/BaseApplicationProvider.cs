namespace Framework.Security.OAuth.ApplicationProviders
{
    using System;

    public abstract class BaseApplicationProvider : IApplicationProvider
    {
        #region Methods

        public virtual string CreateToken(IApplication application, string userId)
        {
            return Guid.NewGuid().ToString("n");
        }

        public virtual void DeleteUserToken(IApplication application, string userId, string token)
        {
        }

        public virtual void SaveUserToken(IApplication application, string userId, string token)
        {
        }

        public abstract bool ValidateApplication(string id, string secret, out IApplication application);

        public virtual bool ValidateUserRefreshToken(string token, IApplication application, out IUser user)
        {
            user = null;
            return true;
        }

        #endregion Methods
    }
}