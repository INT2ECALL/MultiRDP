using System;
using System.IO;
using System.Text;
using Microsoft.Win32;
using System.Threading;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Security.Permissions;
using System.Security.Principal;

namespace MultiRDP
{
    public class Program
    {
        public static byte[] PatchFind = { };
        public static byte[] PatchReplace = {0xB8,0x00,0x01,0x00,0x00,0x89,0x81,0x38,0x06,0x00,0x00,0x90};

        private static void Banner()
        {
            Console.WriteLine("\n-~=[Multiple RDP Sessions]=~-");
            Console.WriteLine("* Allows system administrators to carryout administration tasks without disturbing the user");
            Console.WriteLine("// With love from Snow Leopard //");
        }
        static void Main(string[] args)
        {
            if (!isAdminRight())
            {
                Console.WriteLine("[!] I need administrator rights to patch.");
                System.Environment.Exit(0);
            }

            try
            {
                string termsrv_src = "C:\\W"+"indo"+"ws\\Sys"+"tem3"+"2\\t"+"erms"+"rv.d"+"ll";
                FileVersionInfo ver = FileVersionInfo.GetVersionInfo(termsrv_src);
                Console.WriteLine("[*] Found dll with version: " + ver.ProductVersion);
                GetAptPatch(ver.ProductVersion);

                Console.WriteLine("[*] Stopping termservice");
                ShellCmd(@"net stop termservice /y");

                ShellCmd("sc config TrustedInstaller binPath= \"cmd /c move C:\\Windows\\System32\\termsrv.dll C:\\Users\\Public\\termsrv.dll\"");
                ShellCmd("sc start \"TrustedInstaller\"");
                Thread.Sleep(3000);

                Console.WriteLine("\n[*] Patching...");
                PatchFile(@"C:\Users\Pub" + @"lic\term"+ @"srv.d"+ "ll", @"C:\Us"+@"ers\P"+@"ublic"+@"\ter"+@"msrv2.d"+@"ll");
                Thread.Sleep(3000);

                ShellCmd("sc config TrustedInstaller binPath= \"cmd /c move C:\\Users\\P"+"ublic\\te"+"rmsrv2.d"+"ll C:\\Windows\\S"+"yste"+"m32\\ter"+"msrv.dll\"");
                ShellCmd("sc start \"TrustedInstaller\"");
                Thread.Sleep(2000);

                ShellCmd("icacls \"C:\\Windows\\System32\\termsrv.dll\" /setowner \"NT SERVICE\\TrustedInstaller\"");
                ShellCmd("icacls \"C:\\Windows\\System32\\termsrv.dll\" /grant \"NT SERVICE\\TrustedInstaller:(RX)\"");

                Console.WriteLine("[*] Setting the Registry entry");
                RegistryKey reg_key1 = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
                reg_key1.SetValue("fSingleSessionPerUser", 0, RegistryValueKind.DWord);
                RegistryKey reg_key2 = Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList");
                reg_key2.SetValue("fDisabledAllowList", 1, RegistryValueKind.DWord);

                Console.WriteLine("[*] Starting termservice again");
                ShellCmd(@"net start termservice /y");

                Console.WriteLine("[*] Finito");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }

        static bool ShellCmd(string cmd)
        {
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            process.StartInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " + cmd;

            return process.Start();
        }

        public static bool isAdminRight()
        {
            bool isElevated;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);

                return isElevated;
            }
        }

        private static void GetAptPatch(string termsrvVersion)
        {
            // www.mysysadmintips.com/windows/clients/545-multiple-rdp-remote-desktop-sessions-in-windows-10
            if (termsrvVersion == "10.0.19041.1023")
            {
                PatchFind = new byte[]
                {
                    0x39,0x81,0x3C,0x06,0x00,0x00,0x0F,0x84,0x21,0x68,0x01,0x00
                };
            }
            if (termsrvVersion == "10.0.19041.84")
            {
                PatchFind = new byte[]
                {
                    0x39 ,0x81 ,0x3C ,0x06 ,0x00 ,0x00 ,0x0F ,0x84 ,0xD9 ,0x51 ,0x01 ,0x00 
                };
            }
            if (termsrvVersion == "10.0.18362.657")
            {
                PatchFind = new byte[]
                {
                    0x39 ,0x81 ,0x3C ,0x06 ,0x00 ,0x00 ,0x0F ,0x84 ,0x5D ,0x61 ,0x01 ,0x00 
                };
            }
            if (termsrvVersion == "10.0.18362.53")
            {
                PatchFind = new byte[]
                {
                    0x39,0x81 ,0x3C ,0x06 ,0x00 ,0x00 ,0x0F ,0x84 ,0x5D ,0x61 ,0x01 ,0x00
                };
            }
            if (termsrvVersion == "10.0.17763.1")
            {
                PatchFind = new byte[] {
                   0x39,0x81,0x3C,0x06,0x00,0x00,0x0F,0x84,0x7F,0x2C,0x01,0x00
                };
            }
            else if (termsrvVersion == "10.0.17763.437")
            {
                PatchFind = new byte[] {
                   0x39,0x81,0x3C,0x06,0x00,0x00,0x0F,0x84,0x3B,0x2B,0x01,0x00
                };
            }
            else if (termsrvVersion == "10.0.17134.1")
            {
                PatchFind = new byte[] {
                    0x8B,0x99,0x3C,0x06,0x00,0x00,0x8B,0xB9,0x38,0x06,0x00,0x00
                };
            }
            else if (termsrvVersion == "10.0.16299.15")
            {
                PatchFind = new byte[] {
                    0x39,0x81,0x3C,0x06,0x00,0x00,0x0F,0x84,0xB1,0x7D,0x02,0x00
                };
            }
            else if (termsrvVersion == "10.0.10240.16384")
            {
                PatchFind = new byte[] {
                    0x39,0x81,0x3C,0x06,0x00,0x00,0x0F,0x84,0x73,0x42,0x02,0x00
                };
            }
            else if (termsrvVersion == "10.0.10586.0")
            {
                PatchFind = new byte[] {
                    0x39,0x81,0x3C,0x06,0x00,0x00,0x0F,0x84,0x3F,0x42,0x02,0x00
                };
            }
            else
            {
                Console.WriteLine("[!] Unknown Version");
                System.Environment.Exit(0);
            }
        }

        private static bool DetectPatch(byte[] sequence, int position)
        {
            if (position + PatchFind.Length > sequence.Length) return false;
            for (int p = 0; p < PatchFind.Length; p++)
            {
                if (PatchFind[p] != sequence[position + p]) return false;
            }
            return true;
        }

        private static void PatchFile(string originalFile, string patchedFile)
        {
            // Ensure target directory exists.
            var targetDirectory = Path.GetDirectoryName(patchedFile);

            // Read file bytes.
            byte[] fileContent = File.ReadAllBytes(originalFile);

            for (int p = 0; p < fileContent.Length; p++)
            {
                bool isPatch = DetectPatch(fileContent, p);
                if (!isPatch) continue;

                for (int w = 0; w < PatchFind.Length; w++)
                {
                    fileContent[p + w] = PatchReplace[w];
                }
            }

            // Save it to another location.
            File.WriteAllBytes(patchedFile, fileContent);
            Console.WriteLine("[*] Patched successfully");
        }
    }
}
