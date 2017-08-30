package org.spongycastle.tls.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.spongycastle.tls.DigitallySigned;
import org.spongycastle.tls.TlsClientProtocol;

class TlsTestClientProtocol extends TlsClientProtocol
{
    protected final TlsTestConfig config;

    public TlsTestClientProtocol(InputStream input, OutputStream output, TlsTestConfig config)
    {
        super(input, output);

        this.config = config;
    }

    protected void sendCertificateVerifyMessage(DigitallySigned certificateVerify) throws IOException
    {
        if (certificateVerify.getAlgorithm() != null && config.clientAuthSigAlgClaimed != null)
        {
            certificateVerify = new DigitallySigned(config.clientAuthSigAlgClaimed, certificateVerify.getSignature());
        }

        super.sendCertificateVerifyMessage(certificateVerify);
    }
}
