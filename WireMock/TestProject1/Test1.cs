using Microsoft.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using WireMock.Settings;

namespace TestProject1
{
    [TestClass]
    public sealed class Test1
    {
        [TestMethod]
        public async Task TestMethod1()
        {
            var rootCA = GenerateRootCA();
            var intermdiateCA = GenerateIntermediateCA(rootCA);
            var certFile = GenerateWebServerCertificate(intermdiateCA);
            var settings = new WireMockServerSettings
            {
                Urls = ["https://localhost:9095/"],
                StartAdminInterface = true,
                UseSSL = true,
                CertificateSettings = new WireMockCertificateSettings
                {
                    X509CertificateFilePath = new FileInfo(certFile).FullName,
                }
            };
            var server = WireMockServer.Start(settings);
            server.Given(Request.Create().WithPath("/").UsingGet()).RespondWith(Response.Create().WithStatusCode(200).WithBody("Hello World"));
            // Setup certificate revocation list handling (create two crls and the server to serve them)
            var crlIntermediate = new CertificateRevocationListBuilder().Build(X509CertificateLoader.LoadPkcs12FromFile(intermdiateCA, null), 1, DateTimeOffset.Now.AddYears(99), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var crlServer = WireMockServer.Start(9999);
            crlServer.Given(Request.Create().WithPath("/Intermediate.crl")).RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithHeader(HeaderNames.ContentType, "application/pkix-crl")
                .WithHeader(HeaderNames.ContentDisposition, "attachment; filename=Intermediate.crl")
                .WithHeader(HeaderNames.ContentLength, crlIntermediate.Length.ToString())
                .WithBody(crlIntermediate));
            var crlRoot = new CertificateRevocationListBuilder().Build(X509CertificateLoader.LoadPkcs12FromFile(rootCA, null), 1, DateTimeOffset.Now.AddYears(99), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            crlServer.Given(Request.Create().WithPath("/Root.crl")).RespondWith(
                Response.Create()
                .WithStatusCode(200)
                .WithHeader(HeaderNames.ContentType, "application/pkix-crl")
                .WithHeader(HeaderNames.ContentDisposition, "attachment; filename=Root.crl")
                .WithHeader(HeaderNames.ContentLength, crlRoot.Length.ToString())
                .WithBody(crlRoot));
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
            {
                if (errors == SslPolicyErrors.RemoteCertificateChainErrors)
                {
                    var chain2 = new X509Chain(chain.SafeHandle.DangerousGetHandle());
                    chain2.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust; // We can not use this because .Net 5
                    var serverCertCollection = X509CertificateLoader.LoadPkcs12CollectionFromFile(certFile, null);
                    foreach (var serverCert in serverCertCollection)
                    {
                        chain2.ChainPolicy.ExtraStore.Add(serverCert);
                        chain2.ChainPolicy.CustomTrustStore.Add(serverCert); // This is also .Net5
                    }
                    var valid = chain2.Build(new X509Certificate2(cert));
                    return true;
                }
                return errors == SslPolicyErrors.None;
            };
            using var client = new HttpClient(handler);

            var result = await client.GetStringAsync("https://localhost:9095/");
            Assert.AreEqual("Hello World", result);
            Assert.AreEqual(crlServer.LogEntries.Count, 2); // Two request to the crl server for the root and the intermediate CA
        }

        [TestMethod]
        public async Task GenerateChain()
        {
            var root = GenerateRootCA();
            var intermediate = GenerateIntermediateCA(root);
            var webServer = GenerateWebServerCertificate(intermediate);

        }

        public static string GenerateSelfSignedCertificate()
        {
            string secp256r1Oid = "1.2.840.10045.3.1.7";  //oid for prime256v1(7)  other identifier: secp256r1

            string subjectName = "localhost";

            var ecdsa = ECDsa.Create(ECCurve.CreateFromValue(secp256r1Oid));

            var certRequest = new CertificateRequest($"CN={subjectName}", ecdsa, HashAlgorithmName.SHA256);

            //add extensions to the request (just as an example)
            //add keyUsage
            certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            certRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection() { Oid.FromFriendlyName("Server Authentication", OidGroup.EnhancedKeyUsage) }, true));

            X509Certificate2 generatedCert = certRequest.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(10)); // generate the cert and sign!
            var file = Path.GetTempFileName();
            File.WriteAllBytes(file, generatedCert.Export(X509ContentType.Pfx));
            return file;
        }

        public static string GenerateRootCA()
        {
            var rsa = RSA.Create();

            var certRequest = new CertificateRequest($"CN=RootCA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, false, 0, true));
            certRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certRequest.PublicKey, false));
            certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            //certRequest.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension((string[])["http://localhost:9999/crl.crl"]));

            X509Certificate2 rootCA = certRequest.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(102)); // generate the cert and sign!
            var file = "RootCA.pfx";
            File.WriteAllBytes(file, rootCA.Export(X509ContentType.Pfx));
            return file;
        }

        public static string GenerateIntermediateCA(string rootCA)
        {
            var rootCert = X509CertificateLoader.LoadPkcs12FromFile(rootCA, null);
            var rsa = RSA.Create();
            // Create a certificate request for the intermediate certificate
            var request = new CertificateRequest(
                "CN=IntermediateCA",
                rsa,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            // Set the certificate extensions
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, false, 0, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            request.CertificateExtensions.Add(AuthorityKeyIdentifier(rootCert));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension((string[])["http://localhost:9999/Root.crl"]));
            // Sign the certificate with the root certificate

            var intermediateCert = request.Create(
                rootCert,
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(101),
                Guid.NewGuid().ToByteArray());
            var intermediateCert2 = intermediateCert.CopyWithPrivateKey(rsa);
            X509Certificate2Collection collection = [X509CertificateLoader.LoadCertificate(rootCert.RawData), intermediateCert2];
            var file = "Intermediate.pfx";
            File.WriteAllBytes(file, collection.Export(X509ContentType.Pfx));
            return file;
        }

        public static string GenerateWebServerCertificate(string certificateCA)
        {
            var allCerts = X509CertificateLoader.LoadPkcs12CollectionFromFile(certificateCA, null);
            var rootCert = allCerts.Last();
            var rsa = RSA.Create();
            var certRequest = new CertificateRequest($"CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            //add extensions to the request (just as an example)
            //add keyUsage

            certRequest.CertificateExtensions.Add(AuthorityKeyIdentifier(rootCert));
            certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            certRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([Oid.FromFriendlyName("Server Authentication", OidGroup.EnhancedKeyUsage)], true));
            certRequest.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension((string[])["http://localhost:9999/Intermediate.crl"]));

            X509Certificate2 generatedCert = certRequest.Create(
                rootCert,
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(100),
                Guid.NewGuid().ToByteArray());
            generatedCert = generatedCert.CopyWithPrivateKey(rsa);
            X509Certificate2Collection collection = [.. allCerts.Select(c => X509CertificateLoader.LoadCertificate(c.RawData)), generatedCert];
            var file = "Webserver.pfx";
            File.WriteAllBytes(file, collection.Export(X509ContentType.Pfx));
            return file;
        }

        private static X509AuthorityKeyIdentifierExtension AuthorityKeyIdentifier(X509Certificate2 certificateAuthority) =>
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(certificateAuthority.Extensions.OfType<X509SubjectKeyIdentifierExtension>().First());
    }
}
