package org.spongycastle.asn1.test;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERUTF8String;
import org.spongycastle.asn1.cmc.BodyPartID;
import org.spongycastle.asn1.cmc.BodyPartReference;
import org.spongycastle.asn1.cmc.ControlsProcessed;
import org.spongycastle.util.test.SimpleTest;

public class ControlsProcessedTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new ControlsProcessedTest());
    }

    public String getName()
    {
        return "ControlsProcessedTest";
    }

    public void performTest()
        throws Exception
    {
        ControlsProcessed cp = new ControlsProcessed(new BodyPartReference[]{new BodyPartReference(new BodyPartID(12L)), new BodyPartReference(new BodyPartID(14L))});
        byte[] b = cp.getEncoded();
        ControlsProcessed cpResult = ControlsProcessed.getInstance(b);
        isTrue(cpResult.getBodyList().length == cp.getBodyList().length);
        isEquals(cpResult.getBodyList()[0], cp.getBodyList()[0]);
        isEquals(cpResult.getBodyList()[1], cp.getBodyList()[1]);

        //
        // Incorrect sequence size.
        //

        try
        {
            ControlsProcessed.getInstance(new DERSequence(
                new ASN1Encodable[]{new ASN1Integer(12L), new DERUTF8String("Monkeys")
                }));
            fail("Must accept only sequence length of 1");
        }
        catch (Throwable t)
        {
            isEquals(t.getClass(), IllegalArgumentException.class);
        }
    }

}
