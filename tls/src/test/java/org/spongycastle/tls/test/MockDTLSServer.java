package org.spongycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Vector;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.Certificate;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.AlertLevel;
import org.spongycastle.tls.CertificateRequest;
import org.spongycastle.tls.ClientCertificateType;
import org.spongycastle.tls.DefaultTlsServer;
import org.spongycastle.tls.ProtocolVersion;
import org.spongycastle.tls.SignatureAlgorithm;
import org.spongycastle.tls.TlsCredentialedDecryptor;
import org.spongycastle.tls.TlsCredentialedSigner;
import org.spongycastle.tls.TlsUtils;
import org.spongycastle.tls.crypto.TlsCertificate;
import org.spongycastle.tls.crypto.impl.bc.BcTlsCrypto;

public class MockDTLSServer
    extends DefaultTlsServer
{
    MockDTLSServer()
    {
        super(new BcTlsCrypto(new SecureRandom()));
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS server raised alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
        if (message != null)
        {
            out.println(message);
        }
        if (cause != null)
        {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("DTLS server received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

    public CertificateRequest getCertificateRequest() throws IOException
    {
        short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign,
            ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign };

        Vector serverSigAlgs = null;
        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion))
        {
            serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms(context);
        }

        Vector certificateAuthorities = new Vector();
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-dsa.pem").getSubject());
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-ecdsa.pem").getSubject());
//      certificateAuthorities.addElement(TlsTestUtils.loadBcCertificateResource("x509-ca-rsa.pem").getSubject());

        // All the CA certificates are currently configured with this subject
        certificateAuthorities.addElement(new X500Name("CN=BouncyCastle TLS Test CA"));

        return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
    }

    public void notifyClientCertificate(org.spongycastle.tls.Certificate clientCertificate)
        throws IOException
    {
        TlsCertificate[] chain = clientCertificate.getCertificateList();
        System.out.println("DTLS server received client certificate chain of length " + chain.length);
        for (int i = 0; i != chain.length; i++)
        {
            Certificate entry = Certificate.getInstance(chain[i].getEncoded());
            // TODO Create fingerprint based on certificate signature algorithm digest
            System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " (" + entry.getSubject()
                + ")");
        }
    }

    protected ProtocolVersion getMaximumVersion()
    {
        return ProtocolVersion.DTLSv12;
    }

    protected ProtocolVersion getMinimumVersion()
    {
        return ProtocolVersion.DTLSv10;
    }

    protected TlsCredentialedDecryptor getRSAEncryptionCredentials()
        throws IOException
    {
        return TlsTestUtils.loadEncryptionCredentials(context, new String[]{"x509-server-rsa-enc.pem", "x509-ca-rsa.pem"},
            "x509-server-key-rsa-enc.pem");
    }

    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException
    {
        return TlsTestUtils.loadSignerCredentials(context, supportedSignatureAlgorithms, SignatureAlgorithm.rsa,
            "x509-server-rsa-sign.pem", "x509-server-key-rsa-sign.pem");
    }
}
