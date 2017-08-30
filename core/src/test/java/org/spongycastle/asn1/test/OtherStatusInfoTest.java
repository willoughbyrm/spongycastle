package org.spongycastle.asn1.test;

import java.util.Date;

import org.spongycastle.asn1.ASN1GeneralizedTime;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.cmc.CMCFailInfo;
import org.spongycastle.asn1.cmc.ExtendedFailInfo;
import org.spongycastle.asn1.cmc.OtherStatusInfo;
import org.spongycastle.asn1.cmc.PendInfo;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.util.test.SimpleTest;


public class OtherStatusInfoTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new OtherStatusInfoTest());
    }

    public String getName()
    {
        return "OtherStatusInfoTest";
    }

    public void performTest()
        throws Exception
    {
        {
            OtherStatusInfo ose = OtherStatusInfo.getInstance(CMCFailInfo.badCertId.toASN1Primitive());
            byte[] b = ose.getEncoded();
            OtherStatusInfo oseResult = OtherStatusInfo.getInstance(b);

            isEquals("isFailInfo", oseResult.isFailInfo(), true);
            isEquals("isPendInfo", oseResult.isPendingInfo(), false);
            isEquals("isExtendedFailInfo", oseResult.isExtendedFailInfo(), false);

            isEquals(ose, oseResult);
        }

        {
            OtherStatusInfo ose = OtherStatusInfo.getInstance(new PendInfo("Fish".getBytes(), new ASN1GeneralizedTime(new Date())));
            byte[] b = ose.getEncoded();
            OtherStatusInfo oseResult = OtherStatusInfo.getInstance(b);

            isEquals("isFailInfo", oseResult.isFailInfo(), false);
            isEquals("isPendInfo", oseResult.isPendingInfo(), true);
            isEquals("isExtendedFailInfo", oseResult.isExtendedFailInfo(), false);

            isEquals(ose, oseResult);
        }

        {
            OtherStatusInfo ose = OtherStatusInfo.getInstance(
                new ExtendedFailInfo(PKCSObjectIdentifiers.canNotDecryptAny, new ASN1Integer(10L)));
            byte[] b = ose.getEncoded();
            OtherStatusInfo oseResult = OtherStatusInfo.getInstance(b);

            isEquals("isFailInfo", oseResult.isFailInfo(), false);
            isEquals("isPendInfo", oseResult.isPendingInfo(), false);
            isEquals("isExtendedFailInfo", oseResult.isExtendedFailInfo(), true);

            isEquals(ose, oseResult);
        }
    }
}
