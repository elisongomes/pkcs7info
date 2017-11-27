/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zorpe.pkcs7info;

import java.io.*;
import java.util.*;

import java.text.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.MessageDigest;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.Store;

import org.bouncycastle.asn1.DERUTCTime;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.Extension;
        
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedDataGenerator;

import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.json.simple.JSONValue;
import org.json.simple.JSONObject;


/**
 *
 * @author Elison Gomes
 * @since 24/06/2015
 */
public class Main {
    
    private static final Map        ENCRYPTION_ALGS = new HashMap();
    private static final Map        DIGEST_ALGS = new HashMap();
    
    static
    {
        ENCRYPTION_ALGS.put(X9ObjectIdentifiers.id_dsa_with_sha1.getId(), "DSA");
        ENCRYPTION_ALGS.put(X9ObjectIdentifiers.id_dsa.getId(), "DSA");
        ENCRYPTION_ALGS.put(OIWObjectIdentifiers.dsaWithSHA1.getId(), "DSA");
        ENCRYPTION_ALGS.put(PKCSObjectIdentifiers.rsaEncryption.getId(), "RSA");
        ENCRYPTION_ALGS.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "RSA");
        ENCRYPTION_ALGS.put(TeleTrusTObjectIdentifiers.teleTrusTRSAsignatureAlgorithm, "RSA");
        ENCRYPTION_ALGS.put(X509ObjectIdentifiers.id_ea_rsa.getId(), "RSA");
        ENCRYPTION_ALGS.put(CMSSignedDataGenerator.ENCRYPTION_ECDSA, "ECDSA");
        ENCRYPTION_ALGS.put(X9ObjectIdentifiers.ecdsa_with_SHA2.getId(), "ECDSA");
        ENCRYPTION_ALGS.put(X9ObjectIdentifiers.ecdsa_with_SHA224.getId(), "ECDSA");
        ENCRYPTION_ALGS.put(X9ObjectIdentifiers.ecdsa_with_SHA256.getId(), "ECDSA");
        ENCRYPTION_ALGS.put(X9ObjectIdentifiers.ecdsa_with_SHA384.getId(), "ECDSA");
        ENCRYPTION_ALGS.put(X9ObjectIdentifiers.ecdsa_with_SHA512.getId(), "ECDSA");
        ENCRYPTION_ALGS.put(CMSSignedDataGenerator.ENCRYPTION_RSA_PSS, "RSAandMGF1");
        ENCRYPTION_ALGS.put(CryptoProObjectIdentifiers.gostR3410_94.getId(), "GOST3410");
        ENCRYPTION_ALGS.put(CryptoProObjectIdentifiers.gostR3410_2001.getId(), "ECGOST3410");
        ENCRYPTION_ALGS.put("1.3.6.1.4.1.5849.1.6.2", "ECGOST3410");
        ENCRYPTION_ALGS.put("1.3.6.1.4.1.5849.1.1.5", "GOST3410");

        DIGEST_ALGS.put(PKCSObjectIdentifiers.md5.getId(), "MD5");
        DIGEST_ALGS.put(OIWObjectIdentifiers.idSHA1.getId(), "SHA1");
        DIGEST_ALGS.put(NISTObjectIdentifiers.id_sha224.getId(), "SHA224");
        DIGEST_ALGS.put(NISTObjectIdentifiers.id_sha256.getId(), "SHA256");
        DIGEST_ALGS.put(NISTObjectIdentifiers.id_sha384.getId(), "SHA384");
        DIGEST_ALGS.put(NISTObjectIdentifiers.id_sha512.getId(), "SHA512");
        DIGEST_ALGS.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "SHA1");
        DIGEST_ALGS.put(PKCSObjectIdentifiers.sha224WithRSAEncryption.getId(), "SHA224");
        DIGEST_ALGS.put(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), "SHA256");
        DIGEST_ALGS.put(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), "SHA384");
        DIGEST_ALGS.put(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), "SHA512");
        DIGEST_ALGS.put(TeleTrusTObjectIdentifiers.ripemd128.getId(), "RIPEMD128");
        DIGEST_ALGS.put(TeleTrusTObjectIdentifiers.ripemd160.getId(), "RIPEMD160");
        DIGEST_ALGS.put(TeleTrusTObjectIdentifiers.ripemd256.getId(), "RIPEMD256");
        DIGEST_ALGS.put(CryptoProObjectIdentifiers.gostR3411.getId(),  "GOST3411");
        DIGEST_ALGS.put("1.3.6.1.4.1.5849.1.2.1",  "GOST3411");
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        if (args.length < 4) {
            usage();
            System.exit(0);
        } else if (!args[0].equals("-sf") || !args[2].equals("-cf")) {
            usage();
            System.exit(0);            
        }

        String signedFile = args[1];
        String contentFile = args[3];
        String jsonFile = "";
        
        //Com escrita em arquivo JSON
        if (args.length > 4) {
            if (!args[4].equals("-jf")) {
                usage();
                System.exit(0);
            }
            jsonFile = args[5];
        }
        

        
        String result = "success";
        
        
        JSONObject jsObj = new JSONObject();
        List  jsList = new LinkedList();
        
        try {
            CMSSignedData signedData = new CMSSignedData(new FileInputStream(signedFile));
            
            //Extrair arquivo
            signedData.getSignedContent().write(new FileOutputStream(contentFile));
            
            //processar
            Store certStore = signedData.getCertificates();
            SignerInformationStore signers = signedData.getSignerInfos();
            Iterator it = (Iterator)signers.getSigners().iterator();
            while (it.hasNext()) {
                Map jsMap = new LinkedHashMap();
                
                SignerInformation signer = (SignerInformation)it.next();
                Collection certCollection = certStore.getMatches(signer.getSID());
                Iterator certIt = certCollection.iterator();
                X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
                
                //Nome do emissor
                jsMap.put("issuerName", IETFUtils.valueToString(cert.getIssuer().getRDNs(BCStyle.CN)[0].getFirst().getValue()));
                //Quem assinou
                jsMap.put("subjectName", IETFUtils.valueToString(cert.getSubject().getRDNs(BCStyle.CN)[0].getFirst().getValue()));
                
                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider()).build(cert))) {
                    jsMap.put("verified", 1);
                } else {
                    jsMap.put("verified", 0);
                }
                
                //Algoritmo usado na assinatura
                jsMap.put("algorithm", getDigestAlgName(cert.getSignatureAlgorithm().getAlgorithm().getId()));
                
                //Data de assinatura
                AttributeTable signedAttributesTable = signer.getSignedAttributes();
                DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                String signingTime = df.format(new DERUTCTime(signedAttributesTable.get(CMSAttributes.signingTime).getAttrValues().getObjectAt(0).toString()).getDate());
                jsMap.put("signingTime", signingTime);
                //Validade - FIM
                jsMap.put("notBefore", df.format(cert.getNotBefore()));
                //Validade - FIM
                jsMap.put("notAfter", df.format(cert.getNotAfter()));
                
                //Extensoes
                Extension subjectAlternativeName = cert.getExtension(X509Extensions.SubjectAlternativeName);
                if (subjectAlternativeName != null) {
                    ASN1InputStream ais=new ASN1InputStream(cert.getExtension(X509Extensions.SubjectAlternativeName).getExtnValue().getOctetStream());
                    ASN1Sequence seq=(ASN1Sequence)ais.readObject();
                    GeneralName generalName;
                    Enumeration<?> sit=seq.getObjects();
                    while(sit.hasMoreElements()) {
                        generalName=GeneralName.getInstance(sit.nextElement());
                        if (generalName.getTagNo() == GeneralName.rfc822Name) {
                            jsMap.put("subjectAlternativeName", IETFUtils.valueToString(generalName.getName()));
                        }       
                    }
                }
                jsList.add(jsMap);
            }
            jsObj.put("signers", jsList);
        } catch (Exception e) {
            result = e.getMessage();
        }
        
        jsObj.put("success", result.equals("success") ? 1 : 0);
        if (!result.equals("success")) {
            jsObj.put("message", result);
        }
        
        //Gera arquivo JSON com dados
        if (args.length > 4) {
            try {
                FileWriter file = new FileWriter(jsonFile);
                file.write(jsObj.toJSONString());
                file.flush();
                file.close();
            } catch (IOException e) {
                jsObj.remove("success");
                jsObj.remove("message");
                jsObj.put("success", 0);
                jsObj.put("message", e.getMessage());
            }
        }
        System.out.println(jsObj.toJSONString());
    }
    
    static String getDigestAlgName(String digestAlgOID) {
        String algName = (String) DIGEST_ALGS.get(digestAlgOID);

        if (algName != null) {
            return algName;
        }

        return digestAlgOID;
    }

    static String getEncryptionAlgName(String encryptionAlgOID) {
        String algName = (String) ENCRYPTION_ALGS.get(encryptionAlgOID);

        if (algName != null) {
            return algName;
        }

        return encryptionAlgOID;
    }

    static MessageDigest getDigestInstance(String algorithm, String provider)
            throws NoSuchProviderException, NoSuchAlgorithmException {
        if (provider != null) {
            try {
                return MessageDigest.getInstance(algorithm, provider);
            } catch (NoSuchAlgorithmException e) {
                return MessageDigest.getInstance(algorithm); // try rolling back
            }
        } else {
            return MessageDigest.getInstance(algorithm);
        }
    }
    
    static void usage() {
        String fileName = new File(Main.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getName();
        System.out.println();
        System.out.println("Argumentos invalidos");
        System.out.println();
        System.out.println("Uso: "+fileName+" -sf ArquivoAssinado.p7s -cf ArquivoExtraido.pdf [-jf ArquivoDados.json]");
        System.out.println();
    }
}
