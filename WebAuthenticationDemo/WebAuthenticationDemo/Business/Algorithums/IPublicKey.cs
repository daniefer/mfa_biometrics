using Microsoft.IdentityModel.Tokens;
using PeterO.Cbor;
using WebAuthenticationDemo.Controllers;

namespace WebAuthenticationDemo.Business.Algorithums
{
    /// <summary>
    /// Supported algorithums: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/wiki/Supported-Algorithms
    /// </summary>
    public interface IPublicKey
    {
        string Algorithum { get; }
        SecurityKey GetSecurityKey();
    }
}