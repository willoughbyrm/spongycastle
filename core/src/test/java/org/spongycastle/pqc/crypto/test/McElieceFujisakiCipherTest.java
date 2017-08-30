package org.spongycastle.pqc.crypto.test;

import java.security.SecureRandom;
import java.util.Random;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.pqc.crypto.mceliece.McElieceCCA2KeyGenerationParameters;
import org.spongycastle.pqc.crypto.mceliece.McElieceCCA2KeyPairGenerator;
import org.spongycastle.pqc.crypto.mceliece.McElieceCCA2Parameters;
import org.spongycastle.pqc.crypto.mceliece.McElieceFujisakiCipher;
import org.spongycastle.util.test.SimpleTest;

public class McElieceFujisakiCipherTest
    extends SimpleTest
{

    SecureRandom keyRandom = new SecureRandom();

    public String getName()
    {
        return "McElieceFujisaki";

    }


    public void performTest()
        throws InvalidCipherTextException
    {
        int numPassesKPG = 1;
        int numPassesEncDec = 10;
        Random rand = new Random();
        byte[] mBytes;
        for (int j = 0; j < numPassesKPG; j++)
        {
            McElieceCCA2Parameters params = new McElieceCCA2Parameters();
            McElieceCCA2KeyPairGenerator mcElieceCCA2KeyGen = new McElieceCCA2KeyPairGenerator();
            McElieceCCA2KeyGenerationParameters genParam = new McElieceCCA2KeyGenerationParameters(keyRandom, params);

            mcElieceCCA2KeyGen.init(genParam);
            AsymmetricCipherKeyPair pair = mcElieceCCA2KeyGen.generateKeyPair();

            ParametersWithRandom param = new ParametersWithRandom(pair.getPublic(), keyRandom);
            Digest msgDigest = new SHA256Digest();
            McElieceFujisakiCipher mcElieceFujisakiDigestCipher = new McElieceFujisakiCipher();


            for (int k = 1; k <= numPassesEncDec; k++)
            {
                System.out.println("############### test: " + k);
                // initialize for encryption
                mcElieceFujisakiDigestCipher.init(true, param);

                // generate random message
                int mLength = (rand.nextInt() & 0x1f) + 1;;
                mBytes = new byte[mLength];
                rand.nextBytes(mBytes);

                msgDigest.update(mBytes, 0, mBytes.length);
                byte[] hash = new byte[msgDigest.getDigestSize()];
                msgDigest.doFinal(hash, 0);

                // encrypt
                byte[] enc = mcElieceFujisakiDigestCipher.messageEncrypt(hash);

                // initialize for decryption
                mcElieceFujisakiDigestCipher.init(false, pair.getPrivate());
                byte[] constructedmessage = mcElieceFujisakiDigestCipher.messageDecrypt(enc);

                // XXX write in McElieceFujisakiDigestCipher?


                boolean verified = true;
                for (int i = 0; i < hash.length; i++)
                {
                    verified = verified && hash[i] == constructedmessage[i];
                }

                if (!verified)
                {
                    fail("en/decryption fails");
                }
                else
                {
                    System.out.println("test okay");
                    System.out.println();
                }

            }
        }

    }

    public static void main(
        String[] args)
    {
        runTest(new McElieceFujisakiCipherTest());
    }

}
