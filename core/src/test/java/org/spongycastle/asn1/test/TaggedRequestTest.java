package org.spongycastle.asn1.test;


import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.cmc.BodyPartID;
import org.spongycastle.asn1.cmc.CertificationRequest;
import org.spongycastle.asn1.cmc.TaggedCertificationRequest;
import org.spongycastle.asn1.cmc.TaggedRequest;
import org.spongycastle.asn1.crmf.AttributeTypeAndValue;
import org.spongycastle.asn1.crmf.CertReqMsg;
import org.spongycastle.asn1.crmf.CertRequest;
import org.spongycastle.asn1.crmf.CertTemplate;
import org.spongycastle.asn1.crmf.Controls;
import org.spongycastle.asn1.crmf.POPOSigningKey;
import org.spongycastle.asn1.crmf.POPOSigningKeyInput;
import org.spongycastle.asn1.crmf.ProofOfPossession;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.test.SimpleTest;

public class TaggedRequestTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new TaggedRequestTest());
    }

    public String getName()
    {
        return "TaggedRequestTest";
    }

    private static byte[] req1 = Base64.decode(
        "MIHoMIGTAgEAMC4xDjAMBgNVBAMTBVRlc3QyMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF"
            + "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALlEt31Tzt2MlcOljvacJgzQVhmlMoqAOgqJ9Pgd3Gux"
            + "Z7/WcIlgW4QCB7WZT21O1YoghwBhPDMcNGrHei9kHQkCAwEAAaAAMA0GCSqGSIb3DQEBBQUAA0EA"
            + "NDEI4ecNtJ3uHwGGlitNFq9WxcoZ0djbQJ5hABMotav6gtqlrwKXY2evaIrsNwkJtNdwwH18aQDU"
            + "KCjOuBL38Q==");


    public void performTest()
        throws Exception
    {
        { // TaggedCertificationRequest
            TaggedRequest tr = new TaggedRequest(
                new TaggedCertificationRequest(
                    new BodyPartID(10L),
                    CertificationRequest.getInstance(req1))
            );
            byte[] b = tr.getEncoded();
            TaggedRequest trResult = TaggedRequest.getInstance(b);
            isEquals("Tag", tr.getTagNo(), trResult.getTagNo());
            isEquals("Is TCR tag", TaggedRequest.TCR, tr.getTagNo());
            isEquals("Value", tr.getValue(), trResult.getValue());
        }

        { // CertReqMsg

            POPOSigningKeyInput pski = new POPOSigningKeyInput(
                new GeneralName(GeneralName.rfc822Name, "fish"),
                new SubjectPublicKeyInfo(new AlgorithmIdentifier(
                    PKCSObjectIdentifiers.certBag,
                    new ASN1Integer(5L)), new ASN1Integer(4L)
                ));

            AlgorithmIdentifier aid = new AlgorithmIdentifier(PKCSObjectIdentifiers.crlTypes, new ASN1Integer(1L));
            DERBitString dbi = new DERBitString(2);

            POPOSigningKey popoSigningKey = new POPOSigningKey(pski, aid, dbi);
            ProofOfPossession proofOfPossession = new ProofOfPossession(new POPOSigningKey(pski, aid, dbi));

            TaggedRequest tr = new TaggedRequest(
                new CertReqMsg(new CertRequest(
                    new ASN1Integer(1L),
                    CertTemplate.getInstance(new DERSequence(new DERTaggedObject(0,new ASN1Integer(3L)))),
                    new Controls(new AttributeTypeAndValue(PKCSObjectIdentifiers.pkcs_9,new ASN1Integer(3)))),
                    proofOfPossession,
                    new AttributeTypeAndValue[0])
            );
            byte[] b = tr.getEncoded();
            TaggedRequest trResult = TaggedRequest.getInstance(b);
            isEquals("Tag", tr.getTagNo(), trResult.getTagNo());
            isEquals("Is CRM tag", TaggedRequest.CRM, tr.getTagNo());
            isEquals("Value", tr.getValue(), trResult.getValue());
        }


        { // ORM
            TaggedRequest tr = TaggedRequest.getInstance( new DERTaggedObject(TaggedRequest.ORM, new DERSequence(new ASN1Encodable[]{
                new BodyPartID(1L),
                PKCSObjectIdentifiers.data,
                new DERSet(new ASN1Encodable[]{new ASN1Integer(5L)})
            })));
            byte[] b = tr.getEncoded();
            TaggedRequest trResult = TaggedRequest.getInstance(b);
            isEquals("Tag", tr.getTagNo(), trResult.getTagNo());
            isEquals("Is ORM tag", TaggedRequest.ORM, tr.getTagNo());
            isEquals("Value", tr.getValue(), trResult.getValue());
        }

    }
}
