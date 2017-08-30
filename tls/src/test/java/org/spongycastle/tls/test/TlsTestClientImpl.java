package org.spongycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Encoding;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.Certificate;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.AlertLevel;
import org.spongycastle.tls.CertificateRequest;
import org.spongycastle.tls.ChannelBinding;
import org.spongycastle.tls.ClientCertificateType;
import org.spongycastle.tls.ConnectionEnd;
import org.spongycastle.tls.DefaultTlsClient;
import org.spongycastle.tls.ProtocolVersion;
import org.spongycastle.tls.SignatureAlgorithm;
import org.spongycastle.tls.SignatureAndHashAlgorithm;
import org.spongycastle.tls.TlsAuthentication;
import org.spongycastle.tls.TlsCredentialedSigner;
import org.spongycastle.tls.TlsCredentials;
import org.spongycastle.tls.TlsFatalAlert;
import org.spongycastle.tls.TlsServerCertificate;
import org.spongycastle.tls.TlsUtils;
import org.spongycastle.tls.crypto.TlsCertificate;
import org.spongycastle.tls.crypto.TlsCrypto;
import org.spongycastle.tls.crypto.TlsStreamSigner;
import org.spongycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.spongycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Hex;

class TlsTestClientImpl
    extends DefaultTlsClient
{
    protected final TlsTestConfig config;

    protected int firstFatalAlertConnectionEnd = -1;
    protected short firstFatalAlertDescription = -1;

    byte[] tlsUnique = null;

    TlsTestClientImpl(TlsTestConfig config)
    {
        super(new BcTlsCrypto(new SecureRandom()));

        this.config = config;
    }

    int getFirstFatalAlertConnectionEnd()
    {
        return firstFatalAlertConnectionEnd;
    }

    short getFirstFatalAlertDescription()
    {
        return firstFatalAlertDescription;
    }

    public TlsCrypto getCrypto()
    {
        switch (config.clientCrypto)
        {
        case TlsTestConfig.CRYPTO_JCA:
            return new JcaTlsCryptoProvider().setProvider(new BouncyCastleProvider()).create(new SecureRandom(), new SecureRandom());
        default:
            return new BcTlsCrypto(new SecureRandom());
        }
    }

    public ProtocolVersion getClientVersion()
    {
        if (config.clientOfferVersion != null)
        {
            return config.clientOfferVersion;
        }

        return super.getClientVersion();
    }

    public ProtocolVersion getMinimumVersion()
    {
        if (config.clientMinimumVersion != null)
        {
            return config.clientMinimumVersion;
        }

        return super.getMinimumVersion();
    }

    public Hashtable getClientExtensions() throws IOException
    {
        Hashtable clientExtensions = super.getClientExtensions();
        if (clientExtensions != null && !config.clientSendSignatureAlgorithms)
        {
            clientExtensions.remove(TlsUtils.EXT_signature_algorithms);
            this.supportedSignatureAlgorithms = null;
        }
        return clientExtensions;
    }

    public boolean isFallback()
    {
        return config.clientFallback;
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
        {
            firstFatalAlertConnectionEnd = ConnectionEnd.client;
            firstFatalAlertDescription = alertDescription;
        }

        if (TlsTestConfig.DEBUG)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client raised alert: " + AlertLevel.getText(alertLevel)
                + ", " + AlertDescription.getText(alertDescription));
            if (message != null)
            {
                out.println("> " + message);
            }
            if (cause != null)
            {
                cause.printStackTrace(out);
            }
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        if (alertLevel == AlertLevel.fatal && firstFatalAlertConnectionEnd == -1)
        {
            firstFatalAlertConnectionEnd = ConnectionEnd.server;
            firstFatalAlertDescription = alertDescription;
        }

        if (TlsTestConfig.DEBUG)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client received alert: " + AlertLevel.getText(alertLevel)
                + ", " + AlertDescription.getText(alertDescription));
        }
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        tlsUnique = context.exportChannelBinding(ChannelBinding.tls_unique);

        if (TlsTestConfig.DEBUG)
        {
            System.out.println("TLS client reports 'tls-unique' = " + Hex.toHexString(tlsUnique));
        }
    }

    public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
    {
        super.notifyServerVersion(serverVersion);

        if (TlsTestConfig.DEBUG)
        {
            System.out.println("TLS client negotiated " + serverVersion);
        }
    }

    public TlsAuthentication getAuthentication()
        throws IOException
    {
        return new TlsAuthentication()
        {
            public void notifyServerCertificate(TlsServerCertificate serverCertificate)
                throws IOException
            {
                TlsCertificate[] chain = serverCertificate.getCertificate().getCertificateList();

                if (TlsTestConfig.DEBUG)
                {
                    System.out.println("TLS client received server certificate chain of length " + chain.length);
                    for (int i = 0; i != chain.length; i++)
                    {
                        Certificate entry = Certificate.getInstance(chain[i].getEncoded());
                        // TODO Create fingerprint based on certificate signature algorithm digest
                        System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                            + entry.getSubject() + ")");
                    }
                }

                boolean isEmpty = serverCertificate == null || serverCertificate.getCertificate() == null
                    || serverCertificate.getCertificate().isEmpty();
                if (isEmpty || !TlsTestUtils.isCertificateOneOf(context.getCrypto(), chain[0],
                    new String[]{ "x509-server-dsa.pem", "x509-server-ecdsa.pem", "x509-server-rsa-enc.pem", "x509-server-rsa-sign.pem" }))
                {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);
                }
            }

            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                throws IOException
            {
                if (config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_NONE)
                {
                    throw new IllegalStateException();
                }
                if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_NONE)
                {
                    return null;
                }

                short[] certificateTypes = certificateRequest.getCertificateTypes();
                if (certificateTypes == null || !Arrays.contains(certificateTypes, ClientCertificateType.rsa_sign))
                {
                    return null;
                }

                Vector supportedSigAlgs = certificateRequest.getSupportedSignatureAlgorithms();
                if (supportedSigAlgs != null && config.clientAuthSigAlg != null)
                {
                    supportedSigAlgs = new Vector(1);
                    supportedSigAlgs.addElement(config.clientAuthSigAlg);
                }

                final TlsCredentialedSigner signerCredentials = TlsTestUtils.loadSignerCredentials(context,
                    supportedSigAlgs, SignatureAlgorithm.rsa, "x509-client-rsa.pem", "x509-client-key-rsa.pem");

                if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_VALID)
                {
                    return signerCredentials;
                }

                return new TlsCredentialedSigner()
                {
                    public byte[] generateRawSignature(byte[] hash) throws IOException
                    {
                        byte[] sig = signerCredentials.generateRawSignature(hash);

                        if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_VERIFY)
                        {
                            sig = corruptBit(sig);
                        }

                        return sig;
                    }

                    public org.spongycastle.tls.Certificate getCertificate()
                    {
                        org.spongycastle.tls.Certificate cert = signerCredentials.getCertificate();

                        if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_CERT)
                        {
                            cert = corruptCertificate(context.getCrypto(), cert);
                        }

                        return cert;
                    }

                    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
                    {
                        return signerCredentials.getSignatureAndHashAlgorithm();
                    }

                    public TlsStreamSigner getStreamSigner() throws IOException
                    {
                        return null;
                    }
                };
            }
        };
    }

    protected org.spongycastle.tls.Certificate corruptCertificate(TlsCrypto crypto, org.spongycastle.tls.Certificate cert)
    {
        TlsCertificate[] certList = cert.getCertificateList();
        try
        {
            certList[0] = corruptCertificateSignature(crypto, certList[0]);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
        return new org.spongycastle.tls.Certificate(certList);
    }

    protected TlsCertificate corruptCertificateSignature(TlsCrypto crypto, TlsCertificate tlsCertificate) throws IOException
    {
        Certificate cert = Certificate.getInstance(tlsCertificate.getEncoded());

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(cert.getTBSCertificate());
        v.add(cert.getSignatureAlgorithm());
        v.add(corruptSignature(cert.getSignature()));

        return crypto.createCertificate(Certificate.getInstance(new DERSequence(v)).getEncoded(ASN1Encoding.DER));
    }

    protected DERBitString corruptSignature(DERBitString bs)
    {
        return new DERBitString(corruptBit(bs.getOctets()));
    }

    protected byte[] corruptBit(byte[] bs)
    {
        bs = Arrays.clone(bs);

        // Flip a random bit
        int bit = context.getCrypto().getSecureRandom().nextInt(bs.length << 3);
        bs[bit >>> 3] ^= (1 << (bit & 7));

        return bs;
    }
}
