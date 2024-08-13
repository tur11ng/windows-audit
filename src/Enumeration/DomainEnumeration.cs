using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Security.AccessControl;
using System.Security.Principal;

namespace windows_exploration
{
    public class DomainEnumeration
    {
        public static IEnumerable<UserPrincipal> GetDomainUsers(string domainName)
        {
            domainName = Utilities.GetDomainNameOrDefault(domainName);

            using PrincipalContext context = new(ContextType.Domain, domainName);
            using UserPrincipal userPrincipal = new(context) { Enabled = true };
            using PrincipalSearcher searcher = new(userPrincipal);

            foreach (Principal result in searcher.FindAll())
            {
                UserPrincipal? user = result as UserPrincipal;

                if (user != null)
                {
                    yield return user;
                }
            }
        }

        public static IEnumerable<GroupPrincipal> GetDomainGroups(string domainName)
        {
            domainName = Utilities.GetDomainNameOrDefault(domainName);

            using PrincipalContext context = new(ContextType.Domain, domainName);
            using GroupPrincipal groupPrincipal = new(context);
            using PrincipalSearcher searcher = new(groupPrincipal);

            foreach (Principal result in searcher.FindAll())
            {
                GroupPrincipal? group = result as GroupPrincipal;

                if (group != null)
                {
                    yield return group;
                }
            }
        }

        public static IEnumerable<UserPrincipal> GetGroupMembers(string domainName, GroupPrincipal group, bool recursive)
        {
            domainName = Utilities.GetDomainNameOrDefault(domainName);

            foreach (var principal in group.GetMembers(recursive))
            {
                if (principal is UserPrincipal user)
                {
                    yield return user;
                }
                else if (principal is GroupPrincipal nestedGroup && recursive)
                {
                    foreach (var nestedUser in GetGroupMembers(domainName, nestedGroup, recursive))
                    {
                        yield return nestedUser;
                    }
                }
            }
        }

        public static Dictionary<GroupPrincipal, IEnumerable<UserPrincipal>> GetDomainPrivilegedGroupsMembers(string domainName, bool recursive)
        {
            domainName = Utilities.GetDomainNameOrDefault(domainName);

            var context = new PrincipalContext(ContextType.Domain, domainName);
            var groups = new Dictionary<GroupPrincipal, IEnumerable<UserPrincipal>>();

            foreach (var groupName in PrivilegedGroups)
            {
                var group = GroupPrincipal.FindByIdentity(context, groupName);
                if (group != null)
                {
                    var members = GetGroupMembers(domainName, group, recursive);
                    groups.Add(group, GetGroupMembers(domainName,group, recursive));
                }
            }

            return groups;
        }

        public static IEnumerable<DirectoryEntry> GetDomainObjectsWithInterestingACL(string domainName)
        {
            domainName = Utilities.GetDomainNameOrDefault(domainName);

            string domainPath = $"ldap://{domainName}";

            using (DirectoryEntry entry = new DirectoryEntry(domainPath))
            using (DirectorySearcher searcher = new DirectorySearcher(entry))
            {
                searcher.Filter = "(objectClass=*)";

                foreach (SearchResult result in searcher.FindAll())
                {
                    DirectoryEntry directoryEntry = result.GetDirectoryEntry();
                    if (Utilities.HasObjectInterestingACL(directoryEntry))
                    {
                        yield return directoryEntry;
                    }
                }
            }
        }

        public static List<string> GetEnrollableCertificateTemplates(string domainName)
        {
            domainName = Utilities.GetDomainNameOrDefault(domainName);

            List<string> templates = new List<string>();

            string ldapPath = $"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC={domainName},DC=com";

            WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
            SecurityIdentifier userSid = currentUser.User;

            using (DirectoryEntry entry = new DirectoryEntry(ldapPath))
            {
                foreach (DirectoryEntry child in entry.Children)
                {
                    ActiveDirectorySecurity security = child.ObjectSecurity;

                    AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                    foreach (ActiveDirectoryAccessRule rule in rules)
                    {
                        if (rule.IdentityReference == userSid &&
                            (rule.AccessControlType == AccessControlType.Allow) &&
                            (rule.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.ExtendedRight)) &&
                            (rule.ObjectType == new Guid("0e10c968-78fb-11d2-90d4-00c04f79dc55"))) // Certificate-Enrollment GUID
                        {
                            templates.Add(child.Name);
                            break;
                        }
                    }
                }
            }

            return templates;
        }
    }
}