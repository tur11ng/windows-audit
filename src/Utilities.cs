
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Security.AccessControl;

namespace windows_exploration 
{
    public class Utilities
    {
        public static readonly string[] PrivilegedGroups = new string[] {
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators"
        };
        public static bool IsInterestingACL(ActiveDirectoryAccessRule rule)
        {
            ActiveDirectoryRights[] interestingRights = new ActiveDirectoryRights[]
            {
                ActiveDirectoryRights.GenericAll,
                ActiveDirectoryRights.WriteOwner,
                ActiveDirectoryRights.WriteDacl,
                ActiveDirectoryRights.WriteProperty,
                ActiveDirectoryRights.Delete,
                ActiveDirectoryRights.DeleteTree
            };

            foreach (var right in interestingRights)
            {
                if ((rule.ActiveDirectoryRights & right) == right)
                {
                    return true;
                }
            }

            return false;
        }

        public static bool HasObjectInterestingACL(DirectoryEntry directoryEntry) {
            ActiveDirectorySecurity security = directoryEntry.ObjectSecurity;
            AuthorizationRuleCollection acl = security.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));
            
            foreach (ActiveDirectoryAccessRule rule in acl)
            {
                if (IsInterestingACL(rule)) {
                    return true;
                }
            }

            return false;
        }

        public static string FriendlyDomainToLdapDomain(string friendlyDomainName)
        {

            DirectoryContext objContext = new DirectoryContext(DirectoryContextType.Domain, friendlyDomainName);
            Domain objDomain = Domain.GetDomain(objContext);
            return objDomain.Name;
        }

        private bool Authenticate(string domainName, string userName, string password)
        {
            bool authentic = false;
            try
            {
                DirectoryEntry entry = new DirectoryEntry("LDAP://" + domainName,
                    userName, password);
                object nativeObject = entry.NativeObject;
                authentic = true;
            }
            catch (DirectoryServicesCOMException) { }
            return authentic;
        }
    }
}
