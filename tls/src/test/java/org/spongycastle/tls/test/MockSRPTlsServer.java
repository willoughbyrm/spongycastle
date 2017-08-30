package org.spongycastle.tls.test;

import java.io.IOException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.spongycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.tls.AlertDescription;
import org.spongycastle.tls.AlertLevel;
import org.spongycastle.tls.ProtocolVersion;
import org.spongycastle.tls.SRPTlsServer;
import org.spongycastle.tls.SignatureAlgorithm;
import org.spongycastle.tls.SimulatedTlsSRPIdentityManager;
import org.spongycastle.tls.TlsCredentialedSigner;
import org.spongycastle.tls.TlsSRPIdentityManager;
import org.spongycastle.tls.TlsSRPLoginParameters;
import org.spongycastle.tls.crypto.SRP6Group;
import org.spongycastle.tls.crypto.SRP6StandardGroups;
import org.spongycastle.tls.crypto.TlsCrypto;
import org.spongycastle.tls.crypto.TlsSRPConfig;
import org.spongycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.Strings;

class MockSRPTlsServer
    extends SRPTlsServer
{
    static final SRP6Group TEST_GROUP = SRP6StandardGroups.rfc5054_1024;
    static final byte[] TEST_IDENTITY = Strings.toUTF8ByteArray("client");
    static final byte[] TEST_PASSWORD = Strings.toUTF8ByteArray("password");
    static final byte[] TEST_SALT = Strings.toUTF8ByteArray("salt");
    static final byte[] TEST_SEED_KEY = Strings.toUTF8ByteArray("seed_key");

    MockSRPTlsServer()
        throws IOException
    {
        super(new BcTlsCrypto(new SecureRandom()), new MyIdentityManager(new BcTlsCrypto(new SecureRandom())));
    }

    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-SRP server raised alert: " + AlertLevel.getText(alertLevel) + ", "
            + AlertDescription.getText(alertDescription));
        if (message != null)
        {
            out.println("> " + message);
        }
        if (cause != null)
        {
            cause.printStackTrace(out);
        }
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS-SRP server received alert: " + AlertLevel.getText(alertLevel) + ", "
            + AlertDescription.getText(alertDescription));
    }

    public void notifyHandshakeComplete() throws IOException
    {
        super.notifyHandshakeComplete();

        byte[] srpIdentity = context.getSecurityParameters().getSRPIdentity();
        if (srpIdentity != null)
        {
            String name = Strings.fromUTF8ByteArray(srpIdentity);
            System.out.println("TLS-SRP server completed handshake for SRP identity: " + name);
        }
    }

    protected ProtocolVersion getMinimumVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("TLS-SRP server negotiated " + serverVersion);

        return serverVersion;
    }

    protected TlsCredentialedSigner getDSASignerCredentials() throws IOException
    {
        return TlsTestUtils.loadSignerCredentials(context, supportedSignatureAlgorithms, SignatureAlgorithm.dsa,
            "x509-server-dsa.pem", "x509-server-key-dsa.pem");
    }

    protected TlsCredentialedSigner getRSASignerCredentials() throws IOException
    {
        return TlsTestUtils.loadSignerCredentials(context, supportedSignatureAlgorithms, SignatureAlgorithm.rsa,
            "x509-server-rsa-sign.pem", "x509-server-key-rsa-sign.pem");
    }

    static class MyIdentityManager
        implements TlsSRPIdentityManager
    {
        protected SimulatedTlsSRPIdentityManager unknownIdentityManager;

        MyIdentityManager(TlsCrypto crypto)
            throws IOException
        {
            unknownIdentityManager = SimulatedTlsSRPIdentityManager.getRFC5054Default(crypto, TEST_GROUP, TEST_SEED_KEY);
        }

        public TlsSRPLoginParameters getLoginParameters(byte[] identity)
        {
            if (Arrays.areEqual(TEST_IDENTITY, identity))
            {
                SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();
                verifierGenerator.init(TEST_GROUP.getN(), TEST_GROUP.getG(), new SHA1Digest());

                BigInteger verifier = verifierGenerator.generateVerifier(TEST_SALT, identity, TEST_PASSWORD);

                TlsSRPConfig srpConfig = new TlsSRPConfig();
                srpConfig.setExplicitNG(new BigInteger[]{ TEST_GROUP.getN(), TEST_GROUP.getG() });

                return new TlsSRPLoginParameters(srpConfig, verifier, TEST_SALT);
            }

            return unknownIdentityManager.getLoginParameters(identity);
        }
    }
}
