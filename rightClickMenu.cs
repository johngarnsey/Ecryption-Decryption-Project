using System;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace FolderEncryptionShellExtension
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "-register")
            {
                RegisterShellExtension();
                return;
            }
            
            LaunchEncryptionGUI();
        }
        
        private static void RegisterShellExtension()
        {
            string extensionGuid = "{12345}"; // Unique GUID for the shell extension
            
            // Create registry keys for the shell extension
            using (RegistryKey key = Registry.ClassesRoot.CreateSubKey(@"Folder\shell\EncryptFolder"))
            {
                key.SetValue("", "Encrypt Folder");
                key.SetValue("Icon", "path_to_icon_file");
                
                using (RegistryKey commandKey = key.CreateSubKey("command"))
                {
                    commandKey.SetValue("", $"\"{Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FolderEncryptionShellExtension.exe")}\" \"%1\"");
                }
            }
            
            // Register the shell extension GUID
            using (RegistryKey guidKey = Registry.ClassesRoot.CreateSubKey($@"Directory\shellex\ContextMenuHandlers\{extensionGuid}"))
            {
                guidKey.SetValue("", "FolderEncryptionShellExtension");
            }
        }
        
        private static void LaunchEncryptionGUI()
        {
            string guiPath = "path_to_your_GUI_executable"; // Path to your GUI executable
            
            Process.Start(guiPath);
        }
    }
}
