using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Security.AccessControl;

namespace windows_exploration
{
    public class DomainEnumeration
    {
        private static readonly string[] PrivilegedGroups = new string[] {
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators"
        };

        public static IEnumerable<UserPrincipal> GetDomainUsers(string domainName)
        {
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

        public static IEnumerable<UserPrincipal> GetGroupMembers(GroupPrincipal group, bool recursive)
        {
            foreach (var principal in group.GetMembers(recursive))
            {
                if (principal is UserPrincipal user)
                {
                    yield return user;
                }
                else if (principal is GroupPrincipal nestedGroup && recursive)
                {
                    foreach (var nestedUser in GetGroupMembers(nestedGroup, recursive))
                    {
                        yield return nestedUser;
                    }
                }
            }
        }

        public static Dictionary<GroupPrincipal, IEnumerable<UserPrincipal>> GetDomainPrivilegedGroupsMembers(string domainName, bool recursive)
        {
            var context = new PrincipalContext(ContextType.Domain, domainName);
            var groups = new Dictionary<GroupPrincipal, IEnumerable<UserPrincipal>>();

            foreach (var groupName in PrivilegedGroups)
            {
                var group = GroupPrincipal.FindByIdentity(context, groupName);
                if (group != null)
                {
                    var members = GetGroupMembers(group, recursive);
                    groups.Add(group, GetGroupMembers(group, recursive));
                }
            }

            return groups;
        }

        public static IEnumerable<DirectoryEntry> GetDomainObjectsWithInterestingACL(string domainName) {
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
        
        public static IEnumerable<string> GetCertificatesWithExcessivePermissions(string domainName)
        {
            DirectoryEntry entry = new DirectoryEntry($"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC={domainName}");
            foreach (DirectoryEntry template in entry.Children)
            {
                ActiveDirectorySecurity security = template.ObjectSecurity;
                AuthorizationRuleCollection rules = security.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount));

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    foreach (var groupName in PrivilegedGroups)
                    {
                        if (rule.IdentityReference.Value.Contains(groupName) && rule.AccessControlType == AccessControlType.Allow)
                        {
                            yield return template?.Properties["cn"][0]?.ToString();
                        }
                    }
                }
            }
        }
    }
}