namespace Framework.Security.OAuth.ApplicationProviders
{
    using System;

    public class NoApplicationProvider : BaseApplicationProvider
    {
        #region Methods

        public override bool ValidateApplication(string id, string secret, out IApplication application)
        {
            application = null;
            return true;
        }

        #endregion Methods
    }
}