package com.example.demo.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

import static com.example.demo.Utils.RSAUtil1.generateKeyPair;
import static java.nio.charset.StandardCharsets.UTF_8;

public class CryptoUtil {
    private static final Logger log = LoggerFactory.getLogger(CryptoUtil.class);

    private static final String ALGORITHM = "RSA";

    private static final String CIPHER_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    public static String publicKey =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlynlQjAh2pzdHwSRHIZj+HeOf+lqiSeOmG69ah3RvwbcbkrvxzF5f8+FevIN/q8R17NoOiNpIMeHZAL1BDlHw2Hek66bycoYFWcOWykzBSOU4ccrG1dgX7gzLHCIGiR5dtG5UdwVJ1vff7YUmFcDjc97sA8elTv9pGqzlEFJLiN939IWk+2GK3wVtBXlfUBKf8b366I+PWqSUIPSHqWZkWSwkA5LbMbi2wUi/RpsyREZ4kToPM9FFGGoFyb7zCw6SBLjpJJLaZaUy/kfjHGObSBvIaguFO22s84DCcrZWlIRn9kgPuICrll8jm/yfvhQP42LooWkC114fUCTffjLAQIDAQAB";
    public static String privateKey =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0gnFWUBgcdCTEPj1/enwkypF3h8nnFnHJQ7YAL+PZLTevX962zxV1cA2pqiYgPTo/6wqMpJ/DqjpPT1egmTaJW80cxiy/PKqt/+eH/dJdpbSr4sWDfJAIC4Z7sigu9x0M2YKvTQHJRJiu4LUw5mnQuUieJ2kDRfaIwf8RQMsGGWiuCmF2ObndSZUw2eOJl4PVnhG+QM4eF23NZSPCT2MLcNjZfHDM51zdmx+1avci7i46FE/FVqaHIrVq3vF4rrfjX3RYsvQkXc9QEsqKBa3f1vl7rj1pis6T60Lo8X5N8zBar5Rf3PZHxdWt/Gq4vUM49hwz6GKa8UuQ9DosAD7lAgMBAAECggEAITlTIAZc8bvE2qP0EMccG293Z89D77c3WUqPsKgf4WTLt4lHRlGGSxfFRAGvw8ZRNtuNlQZl648k7V0WrVYV7iFJ9u5Y5RgG+EC+Pk8PDbKGtw5luUZPglOQvKq1b7OHEsrkHVzoo8Fu8t0kLGx0dHjt70Ikt3gEoPZH+sZ4t9XcYkBDu7NmUziiCF9Zw6SbpKqNQj8k9jiZXHcs5i+QeVwlCDQ18+LHtMTi020j5QBZqpAbDg7LlxD+gJigeNAGGvGOMYcprfQYA/qKI1V8CnnXDXUqbANWyYPsuczzKvxdlpN/OKrvFsFae8ogzhcQi9TdHQzGATj8cf9xIMhgHwKBgQD5yox08wo4swhD5K2pFtMYuxvYe8PMnonWdAffny6SspzcQ0t4P2ZJ+seAWOuqA2bEXP3x2Y2Zb3G5IbC/XV+TXYj9yT02D5i2UDTCL7HORsgVVwl0d90qelxAknf0PVoy1Dug4PtH9doEe8t9Rc/dbtZiXYiSlYdENTATz0RmQwKBgQC4/wvqU8VhIG4MwiccWAo0FpbE2KmyVw8G/YArgCCTtw4Fz6sHz1UWayjyXh8c3AkHOM543tpt8hqe2b9WRYgw+H2RixzAO5daQg9fhzYUS4CBv3hQq7DJRlAhqGmJugS8pfpDkNUvlYRZ2LwSoyM/YOSBP6cA2CKyAuXsWwZ3twKBgQCO2XW/v+ndiQ01/oYNx/7LCt4ezJCp6RR8rvh9u0PgIwMvt9BmISO3NRJ4ZOHI5Y8UxvV3JOokkCYiMJEqrxRkaz5XnIlD7GFyCaZSUwJFLBdqlM7Ua2Pw0e8GAn1VEO0PWm4LT/6EJaYboEw8BPud76/sqv7ajWbA7AXlnkfIjwKBgGjfLMIJ+zq0R66z4bgPsLkWlSHCMXEIKVytGJuQZudWPnzM3QfwYSv0U6IR+VFC61tMuL+Mlgb92Fl01yLxB+O6+nQniITxQzvHdy+QVvfqVU84W9xfeDihw4tRDYMmEMlgzh6/XBs9h2nnk7Z9BN5I70DV9LZl0EVZnz393AzBAoGAGC5O2+s+lYocYs6ghakEocr0qMiWsj2CeymH81JomYrvSrcuj2V4iOK54T7xjqWsBzAvMT91HSs7kL/QdXrLfNmS54NUpwwbFpeCmgMWhxWeQ7APDpoAByryk+9upxLuiaLQBfhc5siCQ3eIAdg3km6YWtnaSwoMm6rN0JmSPtY=";



    public static PublicKey getPublicKey(String base64PublicKey) {
        byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
        return getPublicKey(publicKeyBytes);
    }

    public static PublicKey getPublicKey(byte[] publicKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (Exception e) {
            log.error("getPublicKey error", e);
        }
        return null;
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey) {
        byte[] publicKeyBytes = Base64.getDecoder().decode(base64PrivateKey.getBytes(UTF_8));
        return getPrivateKey(publicKeyBytes);
    }

    public static PrivateKey getPrivateKey(byte[] privateKeyBytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        } catch (Exception e) {
            log.error("getPrivateKey error", e);
        }
        return null;
    }

    public static byte[] encrypt(String data, String publicKey)
            throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data.getBytes());
    }

    public static String encryptToBase64(String data, String publicKey)
            throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        return Base64.getEncoder().encodeToString(encrypt(data, publicKey));
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return new String(Base64.getEncoder().encode(signature), UTF_8);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature.getBytes(UTF_8));

        return publicSignature.verify(signatureBytes);
    }

    public static volatile PrivateKey PRIVATE_KEY;
    public static void main(String[] args) throws Exception {

//        addNewKey();
        String a = sign("ThisIsSparta", getPrivateKey(privateKey));

        System.out.println("sign: \n" + a);
    }

    private static void addPrivateKey() throws NoSuchAlgorithmException {
        if (PRIVATE_KEY == null) {
            synchronized (CryptoUtil.class) {
                if (PRIVATE_KEY == null) {
                    KeyPair keyPair = generateKeyPair();
                    PRIVATE_KEY = keyPair.getPrivate();
                }
            }
        }

    }

    public static String generateOTP(int length) {
        // Tập hợp ký tự số từ 0-9
        String characters = "0123456789";
        Random random = new Random();
        StringBuilder otp = new StringBuilder();

        // Vòng lặp tạo OTP
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            otp.append(characters.charAt(index));
        }

        return otp.toString();
    }

    private static void addNewKey() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        String publicKeyStr = new String(Base64.getEncoder().encode(publicKey.getEncoded()), UTF_8);
        System.out.println("Public Key: " + publicKeyStr);
        CryptoUtil.publicKey = publicKeyStr;

        PrivateKey privateKey = keyPair.getPrivate();
        String privateKeyStr = new String(Base64.getEncoder().encode(privateKey.getEncoded()), UTF_8);
        System.out.println("Private Key: " + privateKeyStr);
//        String pemPK = RSAUtil1.privateKeyToPEM(privateKey);
//        System.out.println("Private Key (pemPK): " + pemPK);
        CryptoUtil.privateKey = privateKeyStr;
    }

    // Mã hóa mật khẩu bằng RSA Public Key
    public static String encryptPassword(String password, String publicKeyBase64) throws Exception {
        // Chuyển đổi public key từ chuỗi base64
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        // Mã hóa mật khẩu
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedPassword = cipher.doFinal(password.getBytes());

        // Trả về mật khẩu mã hóa dưới dạng Base64
        return Base64.getEncoder().encodeToString(encryptedPassword);
    }

    // Giải mã mật khẩu bằng RSA Private Key
    public static String decryptPassword(String encryptedPassword, String privateKeyBase64) throws Exception {
        // Chuyển đổi private key từ chuỗi base64
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        // Giải mã mật khẩu
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedPasswordBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));

        // Chuyển đổi lại byte[] thành string
        return new String(decryptedPasswordBytes);
    }
}
