using OpenSSL.Core;
using RsaKeyConverter.Commands;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Input;

namespace RsaKeyConverter.ViewModel
{
    public class MainVindowViewModel : Observable
    {
        private static MainVindowViewModel instance = null;

        public static MainVindowViewModel Instance
        {
            get { return instance ?? (instance = new MainVindowViewModel()); }
        }

        private string xmlRsaPrivate;

        public string XmlRsaPrivate
        {
            get { return xmlRsaPrivate; }
            set { RaisePropertyChanged(() => XmlRsaPrivate, ref xmlRsaPrivate, value); }
        }

        private string xmlRsaPublic;

        public string XmlRsaPublic
        {
            get { return xmlRsaPublic; }
            set { RaisePropertyChanged(() => XmlRsaPublic, ref xmlRsaPublic, value); }
        }

        private string pemRsaPrivate;

        public string PemRsaPrivate
        {
            get { return pemRsaPrivate; }
            set { RaisePropertyChanged(() => PemRsaPrivate, ref pemRsaPrivate, value); }
        }

        private string pemRsaPublic;

        public string PemRsaPublic
        {
            get { return pemRsaPublic; }
            set { RaisePropertyChanged(() => PemRsaPublic, ref pemRsaPublic, value); }
        }

        private string derRsaPrivate;

        public string DerRsaPrivate
        {
            get { return derRsaPrivate; }
            set { RaisePropertyChanged(() => DerRsaPrivate, ref derRsaPrivate, value); }
        }

        private string derRsaPublic;

        public string DerRsaPublic
        {
            get { return derRsaPublic; }
            set { RaisePropertyChanged(() => DerRsaPublic, ref derRsaPublic, value); }
        }

        private ICommand generateNewKey;
        private ICommand convertFromXmlToPemDer;
        private ICommand convertFromPemToXmlDer;
        private ICommand convertFromDerToXmlPem;
        private ICommand exportPem;
        private ICommand exportXml;
        private ICommand exportDer;

        private ICommand clearKeys;

        public ICommand GenerateNewKey
        {
            get
            {
                return generateNewKey ?? (generateNewKey = new DelegateCommand(a =>
                {
                    var rsaCryptoServiceProvider = new RSACryptoServiceProvider();

                    XmlRsaPublic = rsaCryptoServiceProvider.ToXmlString(false);
                    XmlRsaPrivate = rsaCryptoServiceProvider.ToXmlString(true);

                    var rsaPrivateKey = new OpenSSL.Crypto.RSA
                    {
                        SecretPrimeFactorP = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).P),
                        SecretPrimeFactorQ = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).Q),
                        DmodP1 = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).DP),
                        DmodQ1 = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).DQ),
                        IQmodP = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).InverseQ),
                        PrivateExponent = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).D),
                        PublicExponent = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).Exponent),
                        PublicModulus = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).Modulus)
                    };

                    PemRsaPrivate = rsaPrivateKey.PrivateKeyAsPEM;
                    PemRsaPublic = rsaPrivateKey.PublicKeyAsPEM;

                    DerRsaPrivate = BitConverter.ToString(Convert.FromBase64String(PemRsaPrivate.Trim().Substring(31, PemRsaPrivate.Length - 61).Trim()));
                    DerRsaPublic = BitConverter.ToString(Convert.FromBase64String(PemRsaPublic.Trim().Substring(26, PemRsaPublic.Length - 51).Trim()));
                }));
            }
        }

        public ICommand ConvertFromXmlToPemDer
        {
            get
            {
                return convertFromXmlToPemDer ?? (convertFromXmlToPemDer = new DelegateCommand(a =>
                {
                    using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
                    {
                        if (!string.IsNullOrEmpty(XmlRsaPrivate))
                        {
                            rsaCryptoServiceProvider.FromXmlString(XmlRsaPrivate);

                            XmlRsaPublic = rsaCryptoServiceProvider.ToXmlString(false);

                            var rsaPrivateKey = new OpenSSL.Crypto.RSA
                            {
                                SecretPrimeFactorP = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).P),
                                SecretPrimeFactorQ = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).Q),
                                DmodP1 = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).DP),
                                DmodQ1 = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).DQ),
                                IQmodP = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).InverseQ),
                                PrivateExponent = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).D),
                                PublicExponent = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).Exponent),
                                PublicModulus = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(true).Modulus)
                            };

                            PemRsaPrivate = rsaPrivateKey.PrivateKeyAsPEM;
                            PemRsaPublic = rsaPrivateKey.PublicKeyAsPEM;

                            DerRsaPrivate = BitConverter.ToString(Convert.FromBase64String(PemRsaPrivate.Trim().Substring(31, PemRsaPrivate.Length - 61).Trim()));
                            DerRsaPublic = BitConverter.ToString(Convert.FromBase64String(PemRsaPublic.Trim().Substring(26, PemRsaPublic.Length - 51).Trim()));
                        }
                        else if (!string.IsNullOrEmpty(XmlRsaPublic))
                        {
                            rsaCryptoServiceProvider.FromXmlString(XmlRsaPublic);

                            var rsaPublicKey = new OpenSSL.Crypto.RSA
                            {
                                PublicExponent = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(false).Exponent),
                                PublicModulus = BigNumber.FromArray(rsaCryptoServiceProvider.ExportParameters(false).Modulus)
                            };

                            PemRsaPublic = rsaPublicKey.PublicKeyAsPEM;

                            DerRsaPublic = BitConverter.ToString(Convert.FromBase64String(PemRsaPublic.Trim().Substring(26, PemRsaPublic.Length - 51).Trim()));
                        }
                    }

                }, e => !string.IsNullOrEmpty(XmlRsaPrivate) || !string.IsNullOrEmpty(XmlRsaPublic)));
            }
        }

        public ICommand ConvertFromPemToXmlDer
        {
            get
            {
                return convertFromPemToXmlDer ?? (convertFromPemToXmlDer = new DelegateCommand(a =>
                {
                    using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
                    {
                        if (!string.IsNullOrEmpty(PemRsaPrivate))
                        {
                            var rsaPrivateKey = OpenSSL.Crypto.RSA.FromPrivateKey(new BIO(Encoding.ASCII.GetBytes(PemRsaPrivate)));

                            PemRsaPublic = rsaPrivateKey.PublicKeyAsPEM;

                            var rsaParameters = new RSAParameters
                                                    {
                                                        P = rsaPrivateKey.SecretPrimeFactorP,
                                                        Q = rsaPrivateKey.SecretPrimeFactorQ,
                                                        DP = rsaPrivateKey.DmodP1,
                                                        DQ = rsaPrivateKey.DmodQ1,
                                                        InverseQ = rsaPrivateKey.IQmodP,
                                                        D = rsaPrivateKey.PrivateExponent,
                                                        Exponent = rsaPrivateKey.PublicExponent,
                                                        Modulus = rsaPrivateKey.PublicModulus
                                                    };

                            rsaCryptoServiceProvider.ImportParameters(rsaParameters);

                            XmlRsaPrivate = rsaCryptoServiceProvider.ToXmlString(true);
                            XmlRsaPublic = rsaCryptoServiceProvider.ToXmlString(false);

                            DerRsaPrivate = BitConverter.ToString(Convert.FromBase64String(PemRsaPrivate.Trim().Substring(31, PemRsaPrivate.Length - 61).Trim()));
                            DerRsaPublic = BitConverter.ToString(Convert.FromBase64String(PemRsaPublic.Trim().Substring(26, PemRsaPublic.Length - 51).Trim()));
                        }
                        else if (!string.IsNullOrEmpty(PemRsaPublic))
                        {
                            var rsaPrivateKey = OpenSSL.Crypto.RSA.FromPublicKey(new BIO(Encoding.ASCII.GetBytes(PemRsaPublic)));

                            var rsaParameters = new RSAParameters
                                                    {
                                                        Exponent = rsaPrivateKey.PublicExponent,
                                                        Modulus = rsaPrivateKey.PublicModulus
                                                    };

                            rsaCryptoServiceProvider.ImportParameters(rsaParameters);

                            XmlRsaPublic = rsaCryptoServiceProvider.ToXmlString(false);

                            DerRsaPublic = BitConverter.ToString(Convert.FromBase64String(PemRsaPublic.Trim().Substring(26, PemRsaPublic.Length - 51).Trim()));
                        }
                    }
                }, e => !string.IsNullOrEmpty(PemRsaPrivate) || !string.IsNullOrEmpty(PemRsaPublic)));
            }
        }

        public ICommand ConvertFromDerToXmlPem
        {
            get
            {
                return convertFromDerToXmlPem ?? (convertFromDerToXmlPem = new DelegateCommand(a =>
                {
                    using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
                    {
                        if (!string.IsNullOrEmpty(DerRsaPrivate))
                        {
                            byte[] bytes = DerRsaPrivate.Split('-')
                                            .Select(x => byte.Parse(x, NumberStyles.HexNumber))
                                            .ToArray();

                            PemRsaPrivate = "-----BEGIN RSA PRIVATE KEY-----\r\n" + Regex.Replace(Convert.ToBase64String(bytes), "(.{" + 64 + "})", "$1" + "\r\n") + "\r\n-----END RSA PRIVATE KEY-----";

                            var rsaPrivateKey = OpenSSL.Crypto.RSA.FromPrivateKey(new BIO(Encoding.ASCII.GetBytes(PemRsaPrivate)));

                            PemRsaPublic = rsaPrivateKey.PublicKeyAsPEM;

                            var rsaParameters = new RSAParameters
                                                    {
                                                        P = rsaPrivateKey.SecretPrimeFactorP,
                                                        Q = rsaPrivateKey.SecretPrimeFactorQ,
                                                        DP = rsaPrivateKey.DmodP1,
                                                        DQ = rsaPrivateKey.DmodQ1,
                                                        InverseQ = rsaPrivateKey.IQmodP,
                                                        D = rsaPrivateKey.PrivateExponent,
                                                        Exponent = rsaPrivateKey.PublicExponent,
                                                        Modulus = rsaPrivateKey.PublicModulus
                                                    };

                            rsaCryptoServiceProvider.ImportParameters(rsaParameters);

                            XmlRsaPrivate = rsaCryptoServiceProvider.ToXmlString(true);
                            XmlRsaPublic = rsaCryptoServiceProvider.ToXmlString(false);

                            DerRsaPublic = BitConverter.ToString(Convert.FromBase64String(PemRsaPublic.Trim().Substring(26, PemRsaPublic.Length - 51).Trim()));
                        }
                        else if (!string.IsNullOrEmpty(DerRsaPublic))
                        {
                            byte[] bytes = DerRsaPublic .Split('-')
                                                        .Select(x => byte.Parse(x, NumberStyles.HexNumber))
                                                        .ToArray();

                            PemRsaPublic = "-----BEGIN PUBLIC KEY-----\r\n" + Regex.Replace(Convert.ToBase64String(bytes), "(.{" + 64 + "})", "$1" + "\r\n") + "\r\n-----END PUBLIC KEY-----";

                            var rsaPrivateKey = OpenSSL.Crypto.RSA.FromPublicKey(new BIO(Encoding.ASCII.GetBytes(PemRsaPublic)));

                            var rsaParameters = new RSAParameters
                            {
                                Exponent = rsaPrivateKey.PublicExponent,
                                Modulus = rsaPrivateKey.PublicModulus
                            };

                            rsaCryptoServiceProvider.ImportParameters(rsaParameters);

                            XmlRsaPublic = rsaCryptoServiceProvider.ToXmlString(false);
                        }
                    }
                }, e => !string.IsNullOrEmpty(DerRsaPrivate) || !string.IsNullOrEmpty(DerRsaPublic)));
            }
        }

        public ICommand ExportXml
        {
            get
            {
                return exportXml ?? (exportXml = new DelegateCommand(a =>
                {
                    using (var rsaCryptoServiceProvider = new RSACryptoServiceProvider())
                    {
                        if (!string.IsNullOrEmpty(XmlRsaPrivate))
                        {
                            rsaCryptoServiceProvider.FromXmlString(XmlRsaPrivate);

                            XmlRsaPublic = rsaCryptoServiceProvider.ToXmlString(false);

                            File.WriteAllText("private.xml", XmlRsaPrivate);
                            File.WriteAllText("public.xml", XmlRsaPublic);
                        }
                        else if (!string.IsNullOrEmpty(XmlRsaPublic))
                        {
                            File.WriteAllText("public.xml", XmlRsaPublic);
                        }
                    }
                }, e => !string.IsNullOrEmpty(XmlRsaPrivate) || !string.IsNullOrEmpty(XmlRsaPublic)));
            }
        }

        public ICommand ExportPem
        {
            get
            {
                return exportPem ?? (exportPem = new DelegateCommand(a =>
                {
                    if (!string.IsNullOrEmpty(PemRsaPrivate))
                    {
                        var rsaPrivateKey = OpenSSL.Crypto.RSA.FromPrivateKey(new BIO(Encoding.ASCII.GetBytes(PemRsaPrivate)));

                        PemRsaPublic = rsaPrivateKey.PublicKeyAsPEM;

                        File.WriteAllText("private.pem", PemRsaPrivate);
                        File.WriteAllText("public.pem", PemRsaPublic);
                    }
                    else if (!string.IsNullOrEmpty(PemRsaPublic))
                    {
                        File.WriteAllText("public.pem", PemRsaPublic);
                    }
                }, e => !string.IsNullOrEmpty(PemRsaPrivate) || !string.IsNullOrEmpty(PemRsaPublic)));
            }
        }

        public ICommand ExportDer
        {
            get
            {
                return exportDer ?? (exportDer = new DelegateCommand(a =>
                {
                    if (!string.IsNullOrEmpty(DerRsaPrivate))
                    {
                        byte[] bytes = DerRsaPrivate.Split('-')
                                                    .Select(x => byte.Parse(x, NumberStyles.HexNumber))
                                                    .ToArray();

                        string pemRsaPrivateTemp = "-----BEGIN RSA PRIVATE KEY-----\r\n" + Regex.Replace(Convert.ToBase64String(bytes), "(.{" + 64 + "})", "$1" + "\r\n") + "\r\n-----END RSA PRIVATE KEY-----";

                        var rsaPrivateKey = OpenSSL.Crypto.RSA.FromPrivateKey(new BIO(Encoding.ASCII.GetBytes(pemRsaPrivateTemp)));

                        string pemRsaPublicTemp = rsaPrivateKey.PublicKeyAsPEM;

                        File.WriteAllBytes("private.der", bytes);
                        File.WriteAllBytes("public.der", Convert.FromBase64String(pemRsaPublicTemp.Trim().Substring(26, pemRsaPublicTemp.Length - 51).Trim()));
                    }
                    else if (!string.IsNullOrEmpty(DerRsaPublic))
                    {
                        byte[] bytes = DerRsaPublic .Split('-')
                                                    .Select(x => byte.Parse(x, NumberStyles.HexNumber))
                                                    .ToArray();

                        File.WriteAllBytes("public.der", bytes);
                    }
                }, e => !string.IsNullOrEmpty(DerRsaPrivate) || !string.IsNullOrEmpty(DerRsaPublic)));
            }
        }

        public ICommand ClearKeys
        {
            get
            {
                return clearKeys ?? (clearKeys = new DelegateCommand(a =>
                {
                    XmlRsaPrivate = null;
                    XmlRsaPublic = null;
                    PemRsaPrivate = null;
                    PemRsaPublic = null;
                    DerRsaPrivate = null;
                    DerRsaPublic = null;
                }, e => true));
            }
        }
    }
}
