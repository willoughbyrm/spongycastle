package org.spongycastle.asn1.test;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;
import org.spongycastle.asn1.DERUTF8String;
import org.spongycastle.asn1.cmc.BodyPartID;
import org.spongycastle.asn1.cmc.OtherMsg;
import org.spongycastle.asn1.cmc.PKIResponse;
import org.spongycastle.asn1.cmc.TaggedAttribute;
import org.spongycastle.asn1.cmc.TaggedContentInfo;
import org.spongycastle.asn1.cms.ContentInfo;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.util.test.SimpleTest;


public class PKIResponseTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new PKIResponseTest());
    }

    public String getName()
    {
        return "PKIResponseTest";
    }

    public void performTest()
        throws Exception
    {
        PKIResponse pkiResponse = PKIResponse.getInstance(new DERSequence(new ASN1Encodable[]{
            new DERSequence(new TaggedAttribute(new BodyPartID(10L), PKCSObjectIdentifiers.bagtypes, new DERSet())),
            new DERSequence(new TaggedContentInfo(new BodyPartID(12L), new ContentInfo(PKCSObjectIdentifiers.id_aa, new ASN1Integer(10L)))),
            new DERSequence(new OtherMsg(new BodyPartID(12), PKCSObjectIdentifiers.id_aa_msgSigDigest, new DERUTF8String("foo")))
        }));

        byte[] b = pkiResponse.getEncoded();

        PKIResponse pkiResponseResult = PKIResponse.getInstance(b);

        isEquals(pkiResponse, pkiResponseResult);

    }
}
