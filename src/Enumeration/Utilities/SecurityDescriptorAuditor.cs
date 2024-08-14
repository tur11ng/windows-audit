using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using WindowsAudit.Enumeration.Utilities;

namespace WindowsAudit.Enumeration.Utilities
{
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

    public class SecurityDescriptorAuditor
    {
        public static IEnumerable<SecurityDescriptorMisconfiguration> AuditSecurityDescriptorConfiguration(RawSecurityDescriptor? securityDescriptor)
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

            if ((securityDescriptor.ControlFlags & ControlFlags.DiscretionaryAclPresent) != ControlFlags.DiscretionaryAclPresent)
                misconfigurations.Add(SecurityDescriptorMisconfiguration.DACL_NULL);
            else
                misconfigurations.UnionWith(AuditDaclConfiguration(new DiscretionaryAcl(false, false, securityDescriptor.DiscretionaryAcl)));

            if ((securityDescriptor.ControlFlags & ControlFlags.SystemAclPresent) != ControlFlags.SystemAclPresent)
                misconfigurations.Add(SecurityDescriptorMisconfiguration.SACL_NULL);
            else
                misconfigurations.UnionWith(AuditSaclConfiguration(new SystemAcl(false, false, securityDescriptor.SystemAcl)));

            return misconfigurations;
        }

        public static IEnumerable<SecurityDescriptorMisconfiguration> AuditDaclConfiguration(DiscretionaryAcl? acl)
        {
            SecurityIdentifier everyoneSid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
            SecurityIdentifier authenticatedUsersSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            SecurityIdentifier domainUsersSid = new SecurityIdentifier(WellKnownSidType.AccountDomainUsersSid, null);

            var misconfigurations = new HashSet<SecurityDescriptorMisconfiguration>();

            bool seenNonInherited = false;
            bool seenAccessAllowed = false;

            foreach (CommonAce ace in acl)
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

                if (ace.AceType == AceType.AccessAllowed && ace.SecurityIdentifier.Equals(domainUsersSid))
                    misconfigurations.Add(SecurityDescriptorMisconfiguration.DACL_ALLOWS_DOMAIN_USERS);
            }

            return misconfigurations;
        }

        public static IEnumerable<SecurityDescriptorMisconfiguration> AuditSaclConfiguration(SystemAcl? acl)
        {
            var misconfigurations = new HashSet<SecurityDescriptorMisconfiguration>();

            bool seenNonInherited = false;

            if (acl != null)
            {
                foreach (CommonAce ace in acl)
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


