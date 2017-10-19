package com.auth0.jwt.algorithms;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static org.hamcrest.CoreMatchers.is;

public class ECDSATest {

    private static final String public256 = "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQgb5npLHd0Bk61bNnjK632uwmBfr\n" +
            "F7I8hoPgaOZjyhh+BrPDO6CL6D/aW/yPObXXm7SpZogmRwGROcOA3yUleg==\n" +
            "-----END PUBLIC KEY-----\n";
    private static final String private256 = "-----BEGIN PRIVATE KEY-----\n" +
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPGJGAm4X1fvBuC1z\n" +
            "SpO/4Izx6PXfNMaiKaS5RUkFqEGhRANCAARCBvmeksd3QGTrVs2eMrrfa7CYF+sX\n" +
            "sjyGg+Bo5mPKGH4Gs8M7oIvoP9pb/I85tdebtKlmiCZHAZE5w4DfJSV6\n" +
            "-----END PRIVATE KEY-----\n";

    private static final String public384 = "-----BEGIN PUBLIC KEY-----\n" +
            "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEns0hpQLuMAGiXuOu+pkDNBf+bJSPhJHa\n" +
            "bUSXX7ED/ZjcXu0Xcx4HEsO4/1sWuOZ5ZxZxazzy+L4iSjgUcTAdY41QPZsvT4sc\n" +
            "SRqAdtqg0MBWz/JXZhKemm8HQbFzWnjz\n" +
            "-----END PUBLIC KEY-----\n";
    private static final String private384 = "-----BEGIN PRIVATE KEY-----\n" +
            "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCVWQsOJHjKD0I4cXOY\n" +
            "Jm4G8i5c7IMhFbxFq57OUlrTVmND43dvvNW1oQ6i6NiXEQWhZANiAASezSGlAu4w\n" +
            "AaJe4676mQM0F/5slI+EkdptRJdfsQP9mNxe7RdzHgcSw7j/Wxa45nlnFnFrPPL4\n" +
            "viJKOBRxMB1jjVA9my9PixxJGoB22qDQwFbP8ldmEp6abwdBsXNaePM=\n" +
            "-----END PRIVATE KEY-----\n";

    private static final String public512 = "-----BEGIN PUBLIC KEY-----\n" +
            "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAmG8JrpLz14+qUs7oxFX0pCoe90Ah\n" +
            "MMB/9ZENy8KZ+us26i/6PiBBc7XaiEi6Q8Icz2tiazwSpyLPeBrFVPFkPgIADyLa\n" +
            "T0fp7D2JKHWpdrWQvGLLMwGqYCaaDi79KugPo6V4bnpLBlVtbH4ogg0Hqv89BVyI\n" +
            "ZfwWPCBH+Zssei1VlgM=\n" +
            "-----END PUBLIC KEY-----\n";
    private static final String private512 = "-----BEGIN PRIVATE KEY-----\n" +
            "MIHtAgEAMBAGByqGSM49AgEGBSuBBAAjBIHVMIHSAgEBBEHzl1DpZSQJ8YhCbN/u\n" +
            "vo5SOu0BjDDX9Gub6zsBW6B2TxRzb5sBeQaWVscDUZha4Xr1HEWpVtua9+nEQU/9\n" +
            "Aq9Pl6GBiQOBhgAEAJhvCa6S89ePqlLO6MRV9KQqHvdAITDAf/WRDcvCmfrrNuov\n" +
            "+j4gQXO12ohIukPCHM9rYms8Eqciz3gaxVTxZD4CAA8i2k9H6ew9iSh1qXa1kLxi\n" +
            "yzMBqmAmmg4u/SroD6OleG56SwZVbWx+KIINB6r/PQVciGX8FjwgR/mbLHotVZYD\n" +
            "-----END PRIVATE KEY-----\n";


    private Algorithm algorithm256;
    private Algorithm algorithm384;
    private ECDSAAlgorithm algorithm512;


    @Before
    public void setUp() throws Exception {
        algorithm256 = Algorithm.ECDSA256((ECPublicKey) readPublicKeyFromFile(public256, "EC"), (ECPrivateKey) readPrivateKeyFromFile(private256, "EC"));
        algorithm384 = Algorithm.ECDSA384((ECPublicKey) readPublicKeyFromFile(public384, "EC"), (ECPrivateKey) readPrivateKeyFromFile(private384, "EC"));
        algorithm512 = (ECDSAAlgorithm) Algorithm.ECDSA512((ECPublicKey) readPublicKeyFromFile(public512, "EC"), (ECPrivateKey) readPrivateKeyFromFile(private512, "EC"));
    }

    @Test
    public void shouldVerifyNodeGenerated256Token() throws Exception {
        String token = "eyJhbGciOiJFUzI1NiIsImtpZCI6Im15LWtleS1pZCJ9.eyJpc3MiOiJhdXRoMCJ9.D_oU4CB0ZEsxHOjcWnmS3ZJvlTzm6WcGFx-HASxnvcB2Xu2WjI-axqXH9xKq45aPBDs330JpRhJmqBSc2K8MXQ";
        JWTVerifier verifier = JWT.require(algorithm256)
                .build();
        verifier.verify(token);
    }

    @Test
    public void shouldSignUsingECDSA256() throws Exception {
        String signed = JWT.create()
                .withKeyId("my-key-id")
                .withIssuer("auth0")
                .sign(algorithm256);
        System.out.println("Signed: " + signed);

        JWTVerifier verifier = JWT.require(algorithm256)
                .withIssuer("auth0")
                .build();
        verifier.verify(signed);
    }

    @Test
    public void shouldSignUsingECDSA384() throws Exception {
        String signed = JWT.create()
                .withKeyId("my-key-id")
                .withIssuer("auth0")
                .sign(algorithm384);
        System.out.println("Signed: " + signed);

        JWTVerifier verifier = JWT.require(algorithm384)
                .withIssuer("auth0")
                .build();
        verifier.verify(signed);
    }

    @Test
    public void shouldSignUsingECDSA512() throws Exception {
        String signed = JWT.create()
                .withKeyId("my-key-id")
                .withIssuer("auth0")
                .sign(algorithm512);
        System.out.println("Signed: " + signed);

        JWTVerifier verifier = JWT.require(algorithm512)
                .withIssuer("auth0")
                .build();
        verifier.verify(signed);
    }


    @Test
    public void shouldDecode512JOSEWithoutPadding() throws Exception {
        byte[] rNumber = new byte[66];
        byte[] sNumber = new byte[66];
        Arrays.fill(rNumber, (byte) 0x11);
        Arrays.fill(sNumber, (byte) 0x22);
        byte[] joseSignature = new byte[132];
        System.arraycopy(rNumber, 0, joseSignature, 0, 66);
        System.arraycopy(sNumber, 0, joseSignature, 66, 66);

        byte[] derSignature = algorithm512.JOSEToDER(joseSignature);


        Assert.assertThat(derSignature, is(Matchers.notNullValue()));
        Assert.assertThat(derSignature.length, is(139));
        Assert.assertThat(derSignature[0], is((byte) 0x30));
        Assert.assertThat(derSignature[1], is((byte) 0x81));
        Assert.assertThat(derSignature[2], is((byte) 136));
        Assert.assertThat(derSignature[3], is((byte) 0x02));
        Assert.assertThat(derSignature[4], is((byte) 66));

        //5->71 0x11
        byte[] rCopy = Arrays.copyOfRange(derSignature, 5, 71);

        Assert.assertThat(derSignature[71], is((byte) 0x02));
        Assert.assertThat(derSignature[72], is((byte) 66));

        //74->140
        byte[] sCopy = Arrays.copyOfRange(derSignature, 73, 139);

        Assert.assertThat(Arrays.equals(rNumber, rCopy), is(true));
        Assert.assertThat(Arrays.equals(sNumber, sCopy), is(true));
    }

    @Test
    public void shouldDecode512JOSEWithBothPaddings() throws Exception {
        byte[] rNumber = new byte[66];
        byte[] sNumber = new byte[66];
        Arrays.fill(rNumber, (byte) 0x11);
        Arrays.fill(sNumber, (byte) 0x22);
        rNumber[0] = (byte) 0;
        sNumber[0] = (byte) 0;
        byte[] joseSignature = new byte[132];
        System.arraycopy(rNumber, 0, joseSignature, 0, 66);
        System.arraycopy(sNumber, 0, joseSignature, 66, 66);

        byte[] derSignature = algorithm512.JOSEToDER(joseSignature);


        Assert.assertThat(derSignature, is(Matchers.notNullValue()));
        Assert.assertThat(derSignature.length, is(137));
        Assert.assertThat(derSignature[0], is((byte) 0x30));
        Assert.assertThat(derSignature[1], is((byte) 0x81));
        Assert.assertThat(derSignature[2], is((byte) 134));
        Assert.assertThat(derSignature[3], is((byte) 0x02));
        Assert.assertThat(derSignature[4], is((byte) 65));

        //5->71 0x11
        byte[] rCopy = Arrays.copyOfRange(derSignature, 5, 70);

        Assert.assertThat(derSignature[70], is((byte) 0x02));
        Assert.assertThat(derSignature[71], is((byte) 65));
        //73->138 0x22
        byte[] sCopy = Arrays.copyOfRange(derSignature, 72, 137);

        byte[] rExpected = new byte[65];
        byte[] sExpected = new byte[65];
        Arrays.fill(rExpected, (byte) 0x11);
        Arrays.fill(sExpected, (byte) 0x22);
        Assert.assertThat(Arrays.equals(rExpected, rCopy), is(true));
        Assert.assertThat(Arrays.equals(sExpected, sCopy), is(true));
    }


    @Test
    public void shouldDecode512JOSEWithSPadding() throws Exception {
        byte[] rNumber = new byte[66];
        byte[] sNumber = new byte[66];
        Arrays.fill(rNumber, (byte) 0x11);
        Arrays.fill(sNumber, (byte) 0x22);
        sNumber[0] = (byte) 0;
        byte[] joseSignature = new byte[132];
        System.arraycopy(rNumber, 0, joseSignature, 0, 66);
        System.arraycopy(sNumber, 0, joseSignature, 66, 66);

        byte[] derSignature = algorithm512.JOSEToDER(joseSignature);


        Assert.assertThat(derSignature, is(Matchers.notNullValue()));
        Assert.assertThat(derSignature.length, is(138));
        Assert.assertThat(derSignature[0], is((byte) 0x30));
        Assert.assertThat(derSignature[1], is((byte) 0x81));
        Assert.assertThat(derSignature[2], is((byte) 135));
        Assert.assertThat(derSignature[3], is((byte) 0x02));
        Assert.assertThat(derSignature[4], is((byte) 66));

        //5->71 0x11
        byte[] rCopy = Arrays.copyOfRange(derSignature, 5, 71);

        Assert.assertThat(derSignature[71], is((byte) 0x02));
        Assert.assertThat(derSignature[72], is((byte) 65));
        //73->138 0x22
        byte[] sCopy = Arrays.copyOfRange(derSignature, 73, 138);

        byte[] rExpected = new byte[66];
        byte[] sExpected = new byte[65];
        Arrays.fill(rExpected, (byte) 0x11);
        Arrays.fill(sExpected, (byte) 0x22);
        Assert.assertThat(Arrays.equals(rExpected, rCopy), is(true));
        Assert.assertThat(Arrays.equals(sExpected, sCopy), is(true));
    }

    @Test
    public void shouldDecode512JOSEWithRPadding() throws Exception {
        byte[] rNumber = new byte[66];
        byte[] sNumber = new byte[66];
        Arrays.fill(rNumber, (byte) 0x11);
        Arrays.fill(sNumber, (byte) 0x22);
        rNumber[0] = (byte) 0;
        byte[] joseSignature = new byte[132];
        System.arraycopy(rNumber, 0, joseSignature, 0, 66);
        System.arraycopy(sNumber, 0, joseSignature, 66, 66);

        byte[] derSignature = algorithm512.JOSEToDER(joseSignature);


        Assert.assertThat(derSignature, is(Matchers.notNullValue()));
        Assert.assertThat(derSignature.length, is(138));
        Assert.assertThat(derSignature[0], is((byte) 0x30));
        Assert.assertThat(derSignature[1], is((byte) 0x81));
        Assert.assertThat(derSignature[2], is((byte) 135));
        Assert.assertThat(derSignature[3], is((byte) 0x02));
        Assert.assertThat(derSignature[4], is((byte) 65));

        //5->71 0x11
        byte[] rCopy = Arrays.copyOfRange(derSignature, 5, 70);

        Assert.assertThat(derSignature[70], is((byte) 0x02));
        Assert.assertThat(derSignature[71], is((byte) 66));
        //73->138 0x22
        byte[] sCopy = Arrays.copyOfRange(derSignature, 72, 138);

        byte[] rExpected = new byte[65];
        byte[] sExpected = new byte[66];
        Arrays.fill(rExpected, (byte) 0x11);
        Arrays.fill(sExpected, (byte) 0x22);
        Assert.assertThat(Arrays.equals(rExpected, rCopy), is(true));
        Assert.assertThat(Arrays.equals(sExpected, sCopy), is(true));
    }


    @Test
    public void shouldDecode512DERWithoutPadding() throws Exception {
        byte[] rNumber = new byte[66];
        byte[] sNumber = new byte[66];
        Arrays.fill(rNumber, (byte) 0x11);
        Arrays.fill(sNumber, (byte) 0x22);
        byte[] derSignature = new byte[139];
        derSignature[0] = (byte) 0x30;
        derSignature[1] = (byte) 0x81;
        derSignature[2] = (byte) 136;
        derSignature[3] = (byte) 0x02;
        derSignature[4] = (byte) 66;
        System.arraycopy(rNumber, 0, derSignature, 5, 66);
        derSignature[71] = (byte) 0x02;
        derSignature[72] = (byte) 66;
        System.arraycopy(sNumber, 0, derSignature, 73, 66);

        byte[] joseSignature = algorithm512.DERtoJOSE(derSignature);
        Assert.assertThat(joseSignature, is(Matchers.notNullValue()));
        Assert.assertThat(joseSignature.length, is(132));
        byte[] rCopy = Arrays.copyOfRange(joseSignature, 0, 66);
        byte[] sCopy = Arrays.copyOfRange(joseSignature, 66, 132);
        Assert.assertThat(Arrays.equals(rNumber, rCopy), is(true));
        Assert.assertThat(Arrays.equals(sNumber, sCopy), is(true));
    }

    @Test
    public void shouldDecode512DERWithSPadding() throws Exception {
        byte[] rNumber = new byte[66];
        byte[] sNumber = new byte[65];
        Arrays.fill(rNumber, (byte) 0x11);
        Arrays.fill(sNumber, (byte) 0x22);
        byte[] derSignature = new byte[138];
        derSignature[0] = (byte) 0x30;
        derSignature[1] = (byte) 0x81;
        derSignature[2] = (byte) 135;
        derSignature[3] = (byte) 0x02;
        derSignature[4] = (byte) 66;
        System.arraycopy(rNumber, 0, derSignature, 5, 66);
        derSignature[71] = (byte) 0x02;
        derSignature[72] = (byte) 65;
        System.arraycopy(sNumber, 0, derSignature, 73, 65);

        byte[] joseSignature = algorithm512.DERtoJOSE(derSignature);
        Assert.assertThat(joseSignature, is(Matchers.notNullValue()));
        Assert.assertThat(joseSignature.length, is(132));
        byte[] rCopy = Arrays.copyOfRange(joseSignature, 0, 66);
        byte[] sCopy = Arrays.copyOfRange(joseSignature, 66, 132);

        byte[] rExpected = new byte[66];
        byte[] sExpected = new byte[66];
        Arrays.fill(rExpected, (byte) 0x11);
        Arrays.fill(sExpected, (byte) 0x22);
        sExpected[0] = (byte) 0;
        Assert.assertThat(Arrays.equals(rExpected, rCopy), is(true));
        Assert.assertThat(Arrays.equals(sExpected, sCopy), is(true));
    }


//    30 81 87
//    02 42 01 72 d7 50 24 74 3b 39 54 83 03 d0 68 ad f8 61 9e 8c 9b d2 e9 d3 52 d8 67 94 bc 7a 5d 2e 13 7c b7 c9 aa 6e d9 82 a8 e5 3d 59 05 0d d7 d9 d3 2d d0 c9 e5 d8 bd d4 37 6f 70 5f 38 22 04 d0 3a 7f 21 6a
//    02 41 3b 60 73 98 d7 a3 23 3f ba 3f 42 c4 76 28 ba 58 17 6a 9b 34 89 2c 2c 0d 6a 07 68 47 ef 00 9a 10 fd 51 17 af 25 d0 11 6f 3a c2 21 d8 37 00 4c 45 96 45 0c 1f 91 3e 64 b7 18 ec bb 23 41 fb fc ff f7
//    Signed: eyJraWQiOiJteS1rZXktaWQiLCJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.ADtgc5jXoyM_uj9CxHYoulgXaps0iSwsDWoHaEfvAJoQ_VEXryXQEW86wiHYNwBMRZZFDB-RPmS3GOy7I0H7_P_3AXLXUCR0OzlUgwPQaK34YZ6Mm9Lp01LYZ5S8el0uE3y3yapu2YKo5T1ZBQ3X2dMt0Mnl2L3UN29wXzgiBNA6fyFq

    //30 81 86
    //          02 41 51 4f 1f e4 d5 c2 91 46 44 ca f4 09 80 f4 f2 8e 67 43 15 01 17 1b 88 9f 06 e0 11 1b e8 1d f6 1b 7a 03 32 66 26 05 67 ae df 2b 43 eb 01 85 6d c9 82 93 4e 9f dd f9 2e 6c ff 08 e3 e6 76 53 70 c1 39
    //          02 41 27 df 7b 92 e7 0b ed 1a 88 ec 4d 99 fd a8 6c 0e 9e 27 7c 6a 66 9e c2 ce 4e c1 95 41 ef 1e 19 2b df 09 33 68 b3 9c 10 b9 73 7c 00 e4 fc 54 b6 86 53 d7 28 a7 b5 6d 66 b3 1c 10 8a e2 be 77 5f 73 c0


    //                 30 b1 x2 b2  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 x2 b3  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32
    //Length 70, Value 30 44 02 20 14 bd b4 7b 7b 05 fe e3 22 b2 30 72 c1 22 a8 5c d9 df b0 8b 85 95 f9 45 44 5d 0f 40 27 0c 42 f2 02 20 23 62 2f 30 44 04 1c 5f 58 41 a1 c6 a3 3e ab 8b 53 15 86 6a 98 de e3 4c 44 f0 5b c3 08 b0 e6 42
    //Length 70, Value 30 44 02 20 78 ec e7 fc f2 8f 4b 6a 96 66 28 eb 4b f3 7c a1 83 98 60 ae 05 4d 45 37 4e 63 7d d0 c6 a3 4a f1 02 20 58 b0 85 29 5f aa 96 a0 a0 f8 ac 3c d0 27 dd 8f 1c 3c 48 05 4c 82 35 f4 d9 08 5d 47 61 b0 b1 e0
    //Length 70, Value 30 44 02 20 36 33 7e ca 6d ac dd 9c 7a 02 99 b0 7d 55 c8 23 6f d5 b7 64 dc b4 2c 26 73 00 0b 17 87 6c 65 61 02 20 3b 1e 90 90 21 4d 78 97 7e 98 6f 1f f7 6b d1 ce 0e 93 f2 e2 50 33 bd d4 a0 06 86 6f 9c 90 ba fe

    //                 30 b1 x2 b2 pp  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 x2 b3  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32
    //Length 71, Value 30 45 02 21 00 ba bf 6d 61 d5 17 6a 62 d9 e0 13 ae 33 f8 05 b3 c3 8f a3 75 14 b1 2c 1a 70 d7 29 d8 1b ca 2f 73 02 20 55 5d be 8b aa aa 9b 83 37 6e 72 1d a2 b0 6c bc aa 55 01 c2 f8 61 73 1e c9 e3 83 e6 f5 71 5c 5a
    //Length 71, Value 30 45 02 21 00 ae f0 a6 4a df b0 06 86 36 23 f2 c5 6b a3 1e 28 12 c5 02 c4 c9 2c 6b 49 cf ca 18 e5 51 a8 dd 99 02 20 74 11 c2 f9 c3 38 e8 8f ba c9 17 44 a1 20 70 b0 28 84 f8 2a 8d 82 52 86 cb 45 83 4f bb 31 c1 62
    //Length 71, Value 30 45 02 21 00 fd 7e e3 6d 1b 0c 4b 97 db 80 34 59 46 f6 b5 67 f4 3e 86 48 2a 48 e9 3b 9e 45 a2 89 57 ac d1 20 02 20 1c 66 00 07 f5 48 7c e5 d4 18 9a 56 be 71 90 82 19 06 3c 49 c5 97 10 33 97 08 e1 1d 74 77 a9 6a

    //                 30 b1 x2 b2 pp  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 x2 b3 pp  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32
    //Length 72, Value 30 46 02 21 00 d3 88 82 51 5c 83 5d 0f 4d 94 06 3b e7 b1 32 e8 21 c0 d8 80 36 01 70 12 08 73 a4 9a 4c 3e b4 a8 02 21 00 8f 64 72 7c fa ea 34 c7 60 6c ce 2c 76 fc d3 58 6a f1 c7 19 d5 a4 af 37 a3 3f fd a0 29 50 89 d1
    //Length 72, Value 30 46 02 21 00 c2 07 45 cd 68 b8 bc 69 80 a9 af 6c 1d bb 75 18 7f ad 91 57 d1 9f b0 3c e0 a7 36 cc 90 3d 3e d9 02 21 00 a5 23 07 ba 49 39 de 14 b1 6f f3 64 03 03 ce 8f 1b d9 16 4f 26 db 60 40 8e 94 f6 7c f6 6d 04 69
    //Length 72, Value 30 46 02 21 00 8c 85 9f e4 ed 02 e2 91 88 54 63 86 e2 fd 01 e0 97 54 ef a1 75 16 04 78 2d 36 f0 e3 a2 da 60 e9 02 21 00 d6 42 db bf 87 41 63 3e ac 04 14 8e 4a 3a 4c a6 3c a3 0f ad e4 00 83 ca b5 a9 b6 59 d1 76 20 0d


    //private stuff
    private static byte[] parsePEMFile(String stringKey) throws IOException {
        PemReader reader = new PemReader(new StringReader(stringKey));
        PemObject pemObject = reader.readPemObject();
        return pemObject.getContent();
    }

    private static PublicKey getPublicKey(byte[] keyBytes, String algorithm) {
        PublicKey publicKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            publicKey = kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the public key, the given algorithm256 could not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the public key");
        }

        return publicKey;
    }

    private static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm) {
        PrivateKey privateKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            privateKey = kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the private key, the given algorithm256 could not be found.");
        } catch (InvalidKeySpecException e) {
            System.out.println("Could not reconstruct the private key");
        }

        return privateKey;
    }

    private static PublicKey readPublicKeyFromFile(String stringKey, String algorithm) throws IOException {
        byte[] bytes = parsePEMFile(stringKey);
        return getPublicKey(bytes, algorithm);
    }

    private static PrivateKey readPrivateKeyFromFile(String stringKey, String algorithm) throws IOException {
        byte[] bytes = parsePEMFile(stringKey);
        return getPrivateKey(bytes, algorithm);
    }
}
