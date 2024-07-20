
using System.DirectoryServices;
using System.Security.AccessControl;

namespace windows_exploration 
{
    public class Utilities
    {
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
    }
}
