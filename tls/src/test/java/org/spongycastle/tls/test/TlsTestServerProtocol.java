package org.spongycastle.tls.test;

import java.io.InputStream;
import java.io.OutputStream;

import org.spongycastle.tls.TlsServerProtocol;

class TlsTestServerProtocol extends TlsServerProtocol
{
    protected final TlsTestConfig config;

    public TlsTestServerProtocol(InputStream input, OutputStream output, TlsTestConfig config)
    {
        super(input, output);

        this.config = config;
    }
}
