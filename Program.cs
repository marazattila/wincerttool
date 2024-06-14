using System.Security.Cryptography.X509Certificates;

namespace WinCertTool
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                if (args[0] == "add")
                {
                    if (args.Length == 4) { AddCert(args[1], args[2], args[3], null); return; }
                    else if (args.Length == 5) { AddCert(args[1], args[2], args[3], args[4]); return; }
                }
                else if (args[0] == "view")
                {
                    if (args.Length == 3) { ViewCerts(args[1], args[2]); return; }
                }
            }
            PrintHelp();
            return;
        }

        private static void ViewCerts(string storeLocation, string storeName)
        {
            using (var store = new X509Store(ParseStoreName(storeName), ParseStoreLocation(storeLocation)))
            {
                store.Open(OpenFlags.ReadWrite);
                var certs = store.Certificates;
                foreach (var cert in certs)
                {
                    Console.WriteLine(GetCertInfo(cert));
                }
            }
        }

        private static void AddCert(string certPath, string storeLocation, string storeName, string? password)
        {
            using (var store = new X509Store(ParseStoreName(storeName), ParseStoreLocation(storeLocation)))
            {
                var cert = new X509Certificate2(
                    fileName: certPath,
                    password: password,
                    keyStorageFlags: X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);

                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);
                Console.WriteLine($"Certificate {GetCertInfo(cert)} successfully added to {storeLocation}\\{storeName}");
            }
        }

        private static string GetCertInfo(X509Certificate2 cert) => $"Subject: {cert.Subject}, Issuer: {cert.Issuer}, Thumbprint: {cert.Thumbprint}";

        private static StoreName ParseStoreName(string storeName)
        {
            StoreName sn;
            if (storeName == "AddressBook") sn = StoreName.AddressBook;   // Other People
            else if (storeName == "AuthRoot") sn = StoreName.AuthRoot;    // Third-Party Root Certification Authorities
            else if (storeName == "CertificateAuthority") sn = StoreName.CertificateAuthority;    // Intermediate Certification Authorities (certoc.exe = CA)
            else if (storeName == "Disallowed") sn = StoreName.Disallowed;    // Untrusted Certificates
            else if (storeName == "My") sn = StoreName.My;    // Personal
            else if (storeName == "Root") sn = StoreName.Root;    // Trusted Root Certification Authorities (certoc.exe = ROOT)
            else if (storeName == "TrustedPeople") sn = StoreName.TrustedPeople;  // Trusted People
            else if (storeName == "TrustedPublisher") sn = StoreName.TrustedPublisher;    // Trusted Publishers
            else throw new NotSupportedException(storeName);
            return sn;
        }

        private static StoreLocation ParseStoreLocation(string storeLocation)
        {
            StoreLocation sl;
            if (storeLocation == "LocalMachine") sl = StoreLocation.LocalMachine;
            else if (storeLocation == "CurrentUser") sl = StoreLocation.CurrentUser;
            else throw new NotSupportedException(storeLocation);
            return sl;
        }

        private static void PrintHelp()
        {
            Console.WriteLine("No argument found.\r\n" +
                    "Usage: wincerttool [command] [arguments]\r\n" +
                    "\r\n" +
                    "Display or modify certificate.\r\n" +
                    "\r\n" +
                    "commands:\r\n" +
                    "  add\t\tAdd cert. Specify cert path in 1st, StoreLocation in 2nd, StoreName in 3rd argument. Optional password in 4th argument.\r\n" +
                    "  view\t\tList certs. Specify StoreLocation in 1st, StoreName in 2nd argument.\r\n");
        }
    }
}
