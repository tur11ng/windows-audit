
using System.Diagnostics;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;

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

        public static bool HasObjectInterestingACL(DirectoryEntry directoryEntry)
        {
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

        public static IEnumerable<ActiveDirectoryAccessRule> GetObjectInterestingACL(DirectoryEntry directoryEntry)
        {
            ActiveDirectorySecurity security = directoryEntry.ObjectSecurity;
            AuthorizationRuleCollection acl = security.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

            foreach (ActiveDirectoryAccessRule rule in acl)
            {
                if (IsInterestingACL(rule))
                {
                    yield return rule;
                }
            }
        }

        public static bool IsRunningAsAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        static void ElevateToAdministrator()
        {
            var proc = new ProcessStartInfo
            {
                UseShellExecute = true,
                WorkingDirectory = Environment.CurrentDirectory,
                FileName = Process.GetCurrentProcess()?.MainModule?.FileName,
                Verb = "runas"
            };

            Process.Start(proc);
        }
    }
}
