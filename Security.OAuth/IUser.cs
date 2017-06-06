namespace Framework.Security.OAuth
{
    using System;
    using System.Collections.Generic;

    public interface IUser
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

        string Id
        {
            get;
        }

        string[] Roles
        {
            get;
        }

        DateTime TokenIssueDate
        {
            get;
        }

        string Username
        {
            get;
        }

        #endregion Properties
    }
}