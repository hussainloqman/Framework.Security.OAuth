namespace Framework.Security.OAuth
{
    using System.Collections.Generic;

    public interface IApplication
    {
        #region Properties

        Dictionary<string, string> AdditionalResponseParameters
        {
            get;
        }

        Dictionary<string, string> AdditionalTokenParameters
        {
            get;
        }

        string AllowedOrigin
        {
            get;
        }

        string Id
        {
            get;
        }

        string Name
        {
            get;
        }

        int RefreshTokenTimeout
        {
            get;
        }

        #endregion Properties
    }
}