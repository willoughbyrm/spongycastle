package org.spongycastle.tls.test;

import org.spongycastle.tls.DTLSServerProtocol;

class DTLSTestServerProtocol extends DTLSServerProtocol
{
    protected final TlsTestConfig config;

    public DTLSTestServerProtocol(TlsTestConfig config)
    {
        super();

        this.config = config;
    }
}
