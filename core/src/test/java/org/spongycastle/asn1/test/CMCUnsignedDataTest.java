package org.spongycastle.asn1.test;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.cmc.BodyPartID;
import org.spongycastle.asn1.cmc.BodyPartPath;
import org.spongycastle.asn1.cmc.CMCUnsignedData;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.util.test.SimpleTest;


public class CMCUnsignedDataTest
    extends SimpleTest
{

    public static void main(String[] args)
    {
        runTest(new CMCUnsignedDataTest());
    }

    public String getName()
    {
        return "CMCUnsignedDataTest";
    }

    public void performTest()
        throws Exception
    {
        // Encode then decode
        CMCUnsignedData data = new CMCUnsignedData(new BodyPartPath(new BodyPartID(10L)), PKCSObjectIdentifiers.certBag, new DEROctetString("Cats".getBytes()));
        byte[] b = data.getEncoded();
        CMCUnsignedData result = CMCUnsignedData.getInstance(data);

        isEquals(data.getBodyPartPath(), result.getBodyPartPath());
        isEquals(data.getIdentifier(), result.getIdentifier());
        isEquals(data.getContent(), result.getContent());

        // Sequence length must be 3

        try
        {
            CMCUnsignedData.getInstance(new DERSequence(new ASN1Integer(10)));
            fail("Must fail, sequence must be 3");
        }
        catch (Exception ex)
        {
            isEquals(ex.getClass(), IllegalArgumentException.class);
        }

        try
        {
            CMCUnsignedData.getInstance(new DERSequence(new ASN1Encodable[]{new ASN1Integer(10), new ASN1Integer(10), new ASN1Integer(10), new ASN1Integer(10)}));
            fail("Must fail, sequence must be 3");
        }
        catch (Exception ex)
        {
            isEquals(ex.getClass(), IllegalArgumentException.class);
        }

    }
}
