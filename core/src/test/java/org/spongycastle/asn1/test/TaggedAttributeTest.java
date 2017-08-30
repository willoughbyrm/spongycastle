package org.spongycastle.asn1.test;


import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;
import org.spongycastle.asn1.cmc.BodyPartID;
import org.spongycastle.asn1.cmc.CMCObjectIdentifiers;
import org.spongycastle.asn1.cmc.TaggedAttribute;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.test.SimpleTest;


public class TaggedAttributeTest
    extends SimpleTest
{
    public String getName()
    {
        return "TaggedAttributeTest";
    }

    public void performTest()
        throws Exception
    {
        //
        // This creates and tests the various get instance  methods.
        //
        TaggedAttribute ta = new TaggedAttribute(
            new BodyPartID(10L),
            CMCObjectIdentifiers.id_cct_PKIData,
            new DERSet(new DERIA5String("Cats")));

        byte[] d = ta.getEncoded();

        {
            TaggedAttribute res1 = TaggedAttribute.getInstance(d);
            isEquals(ta.getBodyPartID(), res1.getBodyPartID());
            isEquals(ta.getAttrType(), res1.getAttrType());
            isEquals(ta.getAttrValues().getObjectAt(0), res1.getAttrValues().getObjectAt(0));
            isTrue(Arrays.areEqual(res1.getEncoded(), d));
        }

        //
        // Where sequence is too short.
        //
        try
        {
            ASN1Sequence seq = new DERSequence(new ASN1Encodable[] { new BodyPartID(10) });

            TaggedAttribute.getInstance(seq);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("incorrect sequence size", e.getMessage());
        }

        //
        // Where sequence is too long.
        //
        try
        {
            ASN1Sequence seq = new DERSequence(new ASN1Encodable[] { ta.getBodyPartID(), ta.getAttrType(), ta.getAttrValues(), new ASN1Integer(0)});

            TaggedAttribute.getInstance(seq);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("incorrect sequence size", e.getMessage());
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new TaggedAttributeTest());
    }
}
