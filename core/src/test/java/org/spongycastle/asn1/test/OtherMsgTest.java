package org.spongycastle.asn1.test;

import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERUTF8String;
import org.spongycastle.asn1.cmc.BodyPartID;
import org.spongycastle.asn1.cmc.OtherMsg;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.util.test.SimpleTest;


public class OtherMsgTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new OtherMsgTest());
    }

    public String getName()
    {
        return "OtherMsgTest";
    }

    public void performTest()
        throws Exception
    {
        OtherMsg otherMsg = new OtherMsg(new BodyPartID(10L), PKCSObjectIdentifiers.id_aa, new DERUTF8String("Cats"));
        byte[] b = otherMsg.getEncoded();
        OtherMsg otherMsgResult = OtherMsg.getInstance(b);

        isEquals("bodyPartID", otherMsg.getBodyPartID(), otherMsgResult.getBodyPartID());
        isEquals("otherMsgType", otherMsg.getOtherMsgType(), otherMsgResult.getOtherMsgType());
        isEquals("otherMsgValue", otherMsg.getOtherMsgValue(), otherMsgResult.getOtherMsgValue());

        try {
            OtherMsg.getInstance(new DERSequence());
            fail("Sequence should be 3 elements long.");
        } catch (Throwable t) {
            isEquals("Sequence size",t.getClass(), IllegalArgumentException.class);
        }
    }
}
