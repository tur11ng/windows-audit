
using System.Diagnostics;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using static System.Net.Mime.MediaTypeNames;

namespace WindowsAudit.Utilities
{
    public class Misc
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
    }
}
