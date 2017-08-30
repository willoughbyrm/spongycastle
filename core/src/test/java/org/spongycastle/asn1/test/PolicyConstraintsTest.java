package org.spongycastle.asn1.test;

import java.math.BigInteger;

import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.x509.PolicyConstraints;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.test.SimpleTest;

public class PolicyConstraintsTest
    extends SimpleTest
{
    public String getName()
    {
        return "PolicyConstraints";
    }

    public void performTest()
        throws Exception
    {
        PolicyConstraints constraints = new PolicyConstraints(BigInteger.valueOf(1), BigInteger.valueOf(2));

        PolicyConstraints c = PolicyConstraints.getInstance(constraints.getEncoded());

        isTrue("1 requireExplicitPolicyMapping", c.getRequireExplicitPolicyMapping().equals(BigInteger.valueOf(1)));
        isTrue("2 inhibitPolicyMapping", c.getInhibitPolicyMapping().equals(BigInteger.valueOf(2)));

        constraints = new PolicyConstraints(BigInteger.valueOf(3), null);

        c = PolicyConstraints.getInstance(constraints.getEncoded());

        isTrue("3 requireExplicitPolicyMapping", c.getRequireExplicitPolicyMapping().equals(BigInteger.valueOf(3)));
        isTrue("4 inhibitPolicyMapping", c.getInhibitPolicyMapping() == null);


        constraints = new PolicyConstraints(null, BigInteger.valueOf(4));

        c = PolicyConstraints.getInstance(constraints.getEncoded());

        isTrue("5 inhibitPolicyMapping", c.getInhibitPolicyMapping().equals(BigInteger.valueOf(4)));
        isTrue("6 requireExplicitPolicyMapping", c.getRequireExplicitPolicyMapping() == null);

        isTrue("encoding test", Arrays.areEqual(
            new PolicyConstraints(BigInteger.valueOf(1), null).getEncoded(),
            new DERSequence(new DERTaggedObject(false, 0, new ASN1Integer(1))).getEncoded()));
    }

    public static void main(
        String[] args)
    {
        runTest(new PolicyConstraintsTest());
    }
}
