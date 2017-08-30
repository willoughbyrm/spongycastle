package org.spongycastle.test.est;

import java.net.Socket;

import org.spongycastle.est.jcajce.ChannelBindingProvider;
import org.spongycastle.jsse.BCSSLConnection;
import org.spongycastle.jsse.BCSSLSocket;

/**
 * BouncyCastle specific channel binding provider.
 * Access to channel bindings like tls-unique have not been standardised in JSSE.
 * So provider specific implementations must be built.
 */
public class BCChannelBindingProvider
    implements ChannelBindingProvider
{
    public boolean canAccessChannelBinding(Socket sock)
    {
        return sock instanceof BCSSLSocket;
    }

    public byte[] getChannelBinding(Socket sock, String binding)
    {
        BCSSLConnection bcon = ((BCSSLSocket)sock).getConnection();
        if (bcon != null)
        {
            return bcon.getChannelBinding(binding);
        }
        return null;
    }
}
