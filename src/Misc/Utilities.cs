
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using static System.Net.Mime.MediaTypeNames;

namespace windows_exploration 
{
    public class Utilities
    {


        public static bool IsRunningAsLocalAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        [DllImport("shell32.dll", SetLastError = true)]
        static extern IntPtr ShellExecute(
            IntPtr? hwnd,
            string? lpOperation,
            string lpFile,
            string? lpParameters,
            string? lpDirectory,
            int nShowCmd
        );

        static void ElevateToLocalAdministrator()
        {
            var result = 
                ShellExecute(
                    IntPtr.Zero,
                    "runas",
                    Environment.GetCommandLineArgs()[0],
                    null,
                    null,
                    (int)ProcessWindowStyle.Normal
                 );

            if (result <= 32)
            {
                throw new InvalidOperationException();
            }
        }

        public static string GetDomainNameOrDefault(string? domainName)
        {
            return string.IsNullOrEmpty(domainName) ? Domain.GetCurrentDomain().Name : domainName;
        }

        public enum SecurityDescriptorMisconfiguration
        {
            SD_NULL,
            OWNER_NULL,
            GROUP_NULL,
            DACL_NULL,
            SACL_NULL,
            DACL_NON_CANONICAL,
            DACL_ALLOWS_EVERYONE,
            DACL_ALLOWS_AUTHENTICATED_USERS,
            DACL_ALLOWS_DOMAIN_USERS,
            DACL_INHERITANCE_DISABLED,
            SACL_NON_CANONICAL,
            SACL_AUDIT_MISSING,
            NULL_SID_PERMISSIONS,
        }

        public static IEnumerable<SecurityDescriptorMisconfiguration> CheckSecurityDescriptorConfiguration(RawSecurityDescriptor? securityDescriptor)
        {
            var misconfigurations = new HashSet<SecurityDescriptorMisconfiguration>();

            if (securityDescriptor == null)
            {
                misconfigurations.Add(SecurityDescriptorMisconfiguration.SD_NULL);
                return misconfigurations;
            }

            if (securityDescriptor.Owner == null)
                misconfigurations.Add(SecurityDescriptorMisconfiguration.OWNER_NULL);

            if (securityDescriptor.Group == null)
                misconfigurations.Add(SecurityDescriptorMisconfiguration.GROUP_NULL);

            SecurityIdentifier everyoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            SecurityIdentifier authenticatedUsersSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            SecurityIdentifier domainUsersSid = new SecurityIdentifier(WellKnownSidType.AccountDomainUsersSid, null);

            if ((securityDescriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) == ControlFlags.DiscretionaryAclPresent)
            {
                misconfigurations.Add(SecurityDescriptorMisconfiguration.DACL_NULL);
            }
            else
            {
                bool seenNonInherited = false;
                bool seenAccessAllowed = false;

                foreach (CommonAce ace in securityDescriptor.DiscretionaryAcl)
                {
                    bool isInherited = (ace.AceFlags & AceFlags.Inherited) == AceFlags.Inherited;

                    if (isInherited && seenNonInherited)
                        misconfigurations.Add(SecurityDescriptorMisconfiguration.DACL_NON_CANONICAL);

                    if (!isInherited)
                    {
                        seenNonInherited = true;

                        if (ace.AceType == AceType.AccessAllowed)
                            seenAccessAllowed = true;
                        else if (ace.AceType == AceType.AccessDenied && seenAccessAllowed)
                            misconfigurations.Add(SecurityDescriptorMisconfiguration.DACL_NON_CANONICAL);
                    }

                    if (ace.AceType == AceType.AccessAllowed && ace.SecurityIdentifier.Equals(everyoneSid))
                        misconfigurations.Add(SecurityDescriptorMisconfiguration.DACL_ALLOWS_EVERYONE);

                    if (ace.AceType == AceType.AccessAllowed && ace.SecurityIdentifier.Equals(authenticatedUsersSid))
                        misconfigurations.Add(SecurityDescriptorMisconfiguration.DACL_ALLOWS_AUTHENTICATED_USERS);

                    if (ace.AceType == AceType.AccessAllowed && ace.SecurityIdentifier.Equals(authenticatedUsersSid))
                        misconfigurations.Add(SecurityDescriptorMisconfiguration.DACL_ALLOWS_DOMAIN_USERS);
                }
            }

            if ((securityDescriptor.ControlFlags & ControlFlags.SystemAclPresent) == ControlFlags.SystemAclPresent)
            {
                misconfigurations.Add(SecurityDescriptorMisconfiguration.SACL_NULL);
            } else
            {
                bool seenNonInherited = false;

                foreach (CommonAce ace in securityDescriptor.SystemAcl)
                {
                    bool isInherited = (ace.AceFlags & AceFlags.Inherited) == AceFlags.Inherited;

                    if (isInherited && seenNonInherited)
                        misconfigurations.Add(SecurityDescriptorMisconfiguration.SACL_NON_CANONICAL);

                    if (!isInherited)
                    {
                        seenNonInherited = true;
                    }

                    if (ace.AceType == AceType.SystemAudit)
                        misconfigurations.Add(SecurityDescriptorMisconfiguration.SACL_AUDIT_MISSING);
                }
            }

            return misconfigurations;
        }
    }
}
