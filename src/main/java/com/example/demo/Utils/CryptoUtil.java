package com.example.demo.Utils;

import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static com.example.demo.Utils.RSAUtil.generateKeyPair;
import static java.nio.charset.StandardCharsets.UTF_8;

public class CryptoUtil {
    private static final Logger logger = LoggerFactory.getLogger(CryptoUtil.class);
    public static String publicKey =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlynlQjAh2pzdHwSRHIZj+HeOf+lqiSeOmG69ah3RvwbcbkrvxzF5f8+FevIN/q8R17NoOiNpIMeHZAL1BDlHw2Hek66bycoYFWcOWykzBSOU4ccrG1dgX7gzLHCIGiR5dtG5UdwVJ1vff7YUmFcDjc97sA8elTv9pGqzlEFJLiN939IWk+2GK3wVtBXlfUBKf8b366I+PWqSUIPSHqWZkWSwkA5LbMbi2wUi/RpsyREZ4kToPM9FFGGoFyb7zCw6SBLjpJJLaZaUy/kfjHGObSBvIaguFO22s84DCcrZWlIRn9kgPuICrll8jm/yfvhQP42LooWkC114fUCTffjLAQIDAQAB";
    public static String privateKey =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXKeVCMCHanN0fBJEchmP4d45/6WqJJ46Ybr1qHdG/BtxuSu/HMXl/z4V68g3+rxHXs2g6I2kgx4dkAvUEOUfDYd6TrpvJyhgVZw5bKTMFI5ThxysbV2BfuDMscIgaJHl20blR3BUnW99/thSYVwONz3uwDx6VO/2karOUQUkuI33f0haT7YYrfBW0FeV9QEp/xvfroj49apJQg9IepZmRZLCQDktsxuLbBSL9GmzJERniROg8z0UUYagXJvvMLDpIEuOkkktplpTL+R+McY5tIG8hqC4U7bazzgMJytlaUhGf2SA+4gKuWXyOb/J++FA/jYuihaQLXXh9QJN9+MsBAgMBAAECggEAFqCM0rWFu8WTS9tRJWXwfPbYe8kiy1kCfUrGS6YfCWsrf87zyWtcdodHwbmN4rut/g264kj+qYt0dsICjxlL5rE1sgGHDFOV+04r1fV6z6Ad3xYDG9qecHWQI2zM0qz3CZQnG1vIRtX3xJQqzQrpW0bdiuMYfto2A3B9ZQnIvIEUp4t0gmikgCK7Z/cK3iqnRSEWG6o6AO0GlT3tpDLBA7Wx8K9VbWB0ZAl0jEQmkl3XfzncaVWM3yfwkSKaDniwYhUJ64H3yN+a5S7alACreckFRIeF5SFpc4TfrBDUAWb/7S/6iEomJWii7MEaDnAQ1cmsgwpseBvHhvP6SWY5yQKBgQDDZf5lbagvVFa40jxOojhwJrSN58NI1iV8B5bIIoMKAiQzFd+5lm1/DG+4IiX2g/1zay1L0E8oBjVUeZbmIdFYSgnj7eGWAOYz1xCRuE1KSGOAzmpH+teSuYIdwvM/Y8D77pcC10X3/sodw+J7LtQV2owPO773oMT6bBrvj/QBFwKBgQDGC83YWVYfBvk4fIjGXuEW1/4hqGwlSQYoIJ7ik7BwLigtj9xCsjxTP9fyTMREac8S8ZpO8LPvNnGk9EZb4ywYxf8VGRMOX6z+CG9EUgwq0ZVyVF6PSkcHZ5PI3CZAmuRZESMEFbP8gE5iCwIylrOQuS15xfL/Owrn8dhP6t+zpwKBgGoNR3/hfnEBw3fYk2bSYPNt7n0+lx1HLV0d+VZydNDPzLn1W1ItNQzJwTEdR6F+jedA+nq1euDsTbGltKL/I9JZjPiquc9ieY8VYSbV8w0oMOlOHx0mJi66hMaGcuOqzqluG4QtNwqcvTJeiOP2zKF31qDF+qYIGiEY3526ceLNAoGAPT6rQqul6WRzr9c7SPVQcIsNKQV3pDQn9kLYP8Nifd6YSDbD69BIvYnx0xmQXIPIKNiUWrMvQdu5W0S7eXEQUvzv/GtLrFdEHS8okZ057AfySm/y6icTPiP23NfP8Iy17yFQjdPUXFKlasZywIhAMZJCkPT5R5rPrZjpxxUgZuMCgYEApG6E0txTFFg7+Nht2/alsJWTB5YwyaWr6RFA0m518rHgpcJhJiPN8cipV/6d82nxn/r3sICtxu/ja8xZRYNLnqvCj+3WahBhsUt4PTLCX01/vpXSN9dGeT79XvktrlpB+18FHhOmVWm66xukfI45yZ7dtPAivzjLlDgm9itrOgs=";

    public static PublicKey getPublicKeySHA256withRSA(String base64PublicKey) {
        PublicKey publicKey = null;
        try {
            X509EncodedKeySpec keySpec =
                    new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("SHA256withRSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static PublicKey getPublicKey(String base64PublicKey) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        } catch (Exception e) {
            logger.error("getPublicKey error", e);
        }
        return null;
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(base64PrivateKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        } catch (Exception e) {
            logger.error("getPrivateKey error", e);
        }
        return null;
    }

    public static byte[] encrypt(String data, String publicKey)
            throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException,
                    NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data.getBytes());
    }

    public static String encryptToBase64(String data, String publicKey)
            throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException {
        return Base64.getEncoder().encodeToString(encrypt(data, publicKey));
    }

    public static String decrypt(byte[] data, PrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
                    IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(byte[] data, Key privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
                    IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }

    public static String decrypt(String data, String base64PrivateKey)
            throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException,
                    NoSuchPaddingException {
        return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey));
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    public static void main(String[] args)
            throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException {
        addNewKey();
        try {
            String encryptedString = encryptToBase64("245987", publicKey);
            System.out.println("encryptedString: " + encryptedString);
            String decryptedString = decrypt(encryptedString, privateKey);
            System.out.println("decryptedString = " + decryptedString);
            //HOTP
            byte[] hmacResult = new HmacUtils(HmacAlgorithms.HMAC_SHA_1, "dhsjdaks")
                    .hmac("32154621");
            // Cắt ngắn HMAC (trích xuất 4 byte từ HMAC và tính OTP)
            int offset = hmacResult[hmacResult.length - 1] & 0x0F;
            int otp = ((hmacResult[offset] & 0x7F) << 24)
                    | ((hmacResult[offset + 1] & 0xFF) << 16)
                    | ((hmacResult[offset + 2] & 0xFF) << 8)
                    | (hmacResult[offset + 3] & 0xFF);

            // Trả về OTP (giới hạn giá trị OTP trong 6 chữ số)
            String abc = String.format("%08d", otp % 100000000);
            System.out.println("HOTP: " + abc);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    private static void addNewKey() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        System.out.println("Public Key: " + publicKeyStr);
        CryptoUtil.publicKey = publicKeyStr;

        String privateKeyStr = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        System.out.println("Private Key: " + privateKeyStr);
        CryptoUtil.privateKey = privateKeyStr;
    }

    // Mã hóa mật khẩu bằng RSA Public Key
    public static String encryptPassword(String password, String publicKeyBase64) throws Exception {
        // Chuyển đổi public key từ chuỗi base64
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        // Mã hóa mật khẩu
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedPassword = cipher.doFinal(password.getBytes());

        // Trả về mật khẩu mã hóa dưới dạng Base64
        return Base64.getEncoder().encodeToString(encryptedPassword);
    }

    // Giải mã mật khẩu bằng RSA Private Key
    public static String decryptPassword(String encryptedPassword, String privateKeyBase64) throws Exception {
        // Chuyển đổi private key từ chuỗi base64
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        // Giải mã mật khẩu
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedPasswordBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));

        // Chuyển đổi lại byte[] thành string
        return new String(decryptedPasswordBytes);
    }
}
