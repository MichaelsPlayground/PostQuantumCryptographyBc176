package de.androidcrypto.postquantumcryptographybc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowSigner;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PqcRainbowSignature {


    public static void main(String[] args) {
        //Security.addProvider(new BouncyCastleProvider());
        // we do need the regular Bouncy Castle file that includes the PQC provider
        // get Bouncy Castle here: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on
        // tested with BC version 1.76
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        String print = run(false);
        System.out.println(print);
    }

    public static String run(boolean truncateSignatureOutput) {
        String out = "PQC Rainbow signature";

        out += "\n" + "\n************************************\n" +
                "* # # SERIOUS SECURITY WARNING # # *\n" +
                "* This program is a CONCEPT STUDY  *\n" +
                "* for the algorithm                *\n" +
                "* Rainbow [signature]              *\n" +
                "* The program is using an          *\n" +
                "* parameter set that I cannot      *\n" +
                "* check for the correctness of the *\n" +
                "* output and other details         *\n" +
                "*                                  *\n" +
                "*    DO NOT USE THE PROGRAM IN     *\n" +
                "*    ANY PRODUCTION ENVIRONMENT    *\n" +
                "************************************";

        String dataToSignString = "The quick brown fox jumps over the lazy dog";
        byte[] dataToSign = dataToSignString.getBytes(StandardCharsets.UTF_8);

        // as there are 6 parameter sets available the program runs all of them
        RainbowParameterSpec[] rainbowParameterSpecs = {
                RainbowParameterSpec.rainbowIIIclassic,
                RainbowParameterSpec.rainbowIIIcircumzenithal,
                RainbowParameterSpec.rainbowIIIcompressed,
                RainbowParameterSpec.rainbowVclassic,
                RainbowParameterSpec.rainbowVcircumzenithal,
                RainbowParameterSpec.rainbowVcompressed
        };

        // statistics
        int nrOfSpecs = rainbowParameterSpecs.length;
        String[] parameterSpecName = new String[nrOfSpecs];
        int[] privateKeyLength = new int[nrOfSpecs];
        int[] publicKeyLength = new int[nrOfSpecs];
        int[] signatureLength = new int[nrOfSpecs];
        boolean[] signaturesVerified = new boolean[nrOfSpecs];

        out += "\n\n****************************************\n";
        for (int i = 0; i < nrOfSpecs; i++) {
            // generation of the Rainbow key pair
            RainbowParameterSpec rainbowParameterSpec = rainbowParameterSpecs[i];
            String rainbowParameterName = rainbowParameterSpec.getName();
            parameterSpecName[i] = rainbowParameterName;

            out += "\n" + "Rainbow signature with parameterset " + rainbowParameterName;
            // generation of the Rainbow key pair
            KeyPair keyPair = generateRainbowKeyPair(rainbowParameterSpec);

            // get private and public key
            PrivateKey privateKeyRainbow = keyPair.getPrivate();
            PublicKey publicKeyRainbow = keyPair.getPublic();

            // storing the key as byte array
            byte[] privateKeyRainbowByte = privateKeyRainbow.getEncoded();
            byte[] publicKeyRainbowByte = publicKeyRainbow.getEncoded();
            out += "\n" + "\ngenerated private key length: " + privateKeyRainbowByte.length;
            out += "\n" + "generated public key length:  " + publicKeyRainbowByte.length;
            privateKeyLength[i] = privateKeyRainbowByte.length;
            publicKeyLength[i] = publicKeyRainbowByte.length;

            // generate the keys from a byte array
            PrivateKey privateKeyRainbowLoad = getRainbowPrivateKeyFromEncoded(privateKeyRainbowByte);
            PublicKey publicKeyRainbowLoad = getRainbowPublicKeyFromEncoded(publicKeyRainbowByte);


            out += "\n" + "\n* * * sign the dataToSign with the private key * * *";
            byte[] signature = pqcRainbowSignature(privateKeyRainbowLoad, dataToSign);
            out += "\n" + "signature length: " + signature.length + " data: " + (truncateSignatureOutput ? shortenString(bytesToHex(signature)) : bytesToHex(signature));
            signatureLength[i] = signature.length;

            out += "\n" + "\n* * * verify the signature with the public key * * *";
            boolean signatureVerified = pqcRainbowVerification(publicKeyRainbowLoad, dataToSign, signature);
            out += "\n" + "the signature is verified: " + signatureVerified;
            signaturesVerified[i] = signatureVerified;
            out += "\n\n****************************************\n";
        }

        out += "\n" + "Test results";
        out += "\n" + "parameter spec name  priKL   pubKL    sigL  sigV" + "\n";
        for (int i = 0; i < nrOfSpecs; i++) {
            String out1 = String.format("%-20s%6d%8d%8d%6b%n", parameterSpecName[i], privateKeyLength[i], publicKeyLength[i], signatureLength[i], signaturesVerified[i]);
            out += out1;
        }
        out += "\n" + "Legend: priKL privateKey length, pubKL publicKey length, sigL signature length, sigV signature verified\n";
        out += "\n****************************************\n";
        return out;
    }

    private static String shortenString(String input) {
        if (input != null && input.length() > 32) {
            return input.substring(0, 32) + " ...";
        } else {
            return input;
        }
    }

    private static KeyPair generateRainbowKeyPair(RainbowParameterSpec params) {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
            kpg.initialize(params, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                 NoSuchProviderException e) {
            return null;
        }
    }

    private static PrivateKey getRainbowPrivateKeyFromEncoded(byte[] encodedKey) {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("Rainbow", "BCPQC");
            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] pqcRainbowSignature(PrivateKey privateKey, byte[] dataToSign) {
        Signature sig = null;
        try {
            sig = Signature.getInstance("Rainbow", "BCPQC");
            sig.initSign(privateKey, new SecureRandom());
            sig.update(dataToSign, 0, dataToSign.length);
            return sig.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException |
                 InvalidKeyException e) {
            return null;
        }
    }

    private static boolean pqcRainbowVerification(PublicKey publicKey, byte[] dataToSign, byte[] signature) {
        Signature sig = null;
        try {
            sig = Signature.getInstance("Rainbow", "BCPQC");
            sig.initVerify(publicKey);
            sig.update(dataToSign, 0, dataToSign.length);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException |
                 InvalidKeyException e) {
            return false;
        }
    }

    private static PublicKey getRainbowPublicKeyFromEncoded(byte[] encodedKey) {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("Rainbow", "BCPQC");
            return keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }
}