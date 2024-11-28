package com.example.demo.Utils;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import io.micrometer.common.util.StringUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RSAUtil1 {
    private static final Logger log = LoggerFactory.getLogger(RSAUtil1.class);

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static PrivateKey loadPrivateKey(String privateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        log.debug("privateKey: {}", privateKey);
        String standardKey = privateKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace(" ", "")
                .trim();
        log.debug("standard privateKey: {}", standardKey);
        byte[] decoded = Base64.getDecoder().decode(standardKey);
        KeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    public static String decrypt(String privateKey, String encryptedText)
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException,
                    BadPaddingException, InvalidKeyException {
        try {
            if (StringUtils.isNotEmpty(encryptedText)) {
                byte[] bytes = Base64.getDecoder().decode(encryptedText);
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, loadPrivateKey(privateKey));
                byte[] decryptedText = cipher.doFinal(bytes);
                return new String(decryptedText, StandardCharsets.UTF_8);
            }
        } catch (Exception ex) {
            log.error("error when decrypt text", ex);
            throw ex;
        }
        return "";
    }

    // Chuyển đổi private key thành định dạng PEM
    public static String privateKeyToPEM(PrivateKey privateKey) {
        StringWriter stringWriter = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(stringWriter)) {
            pemWriter.writePrivateKey(privateKey.getEncoded());
        } catch (Exception e) {
            log.error("error when generate private key", e);
        }
        return stringWriter.toString();
    }


    public static void main(String[] args) {
        GoogleAuthenticator gAuth = new GoogleAuthenticator();

        // Tạo khóa bí mật
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        System.out.println("Secret Key: " + key.getKey());

        // Tạo mã OTP dựa trên TOTP
        int otp = gAuth.getTotpPassword(key.getKey());
        System.out.println("Generated TOTP: " + otp);

        // Kiểm tra OTP với TOTP
        boolean isValid = gAuth.authorize(key.getKey(), otp);
        System.out.println("Is the OTP valid? " + isValid);

        // HOTP Example: Kiểm tra mã HOTP dựa trên counter
        int counter = 121515;
        otp = gAuth.getTotpPassword(key.getKey(), counter);
        System.out.println("Generated HOTP for counter " + counter + ": " + otp);

        // Kiểm tra tính hợp lệ của HOTP
        isValid = gAuth.authorize(key.getKey(), otp, counter);
        System.out.println("Is the HOTP valid? " + isValid);
    }

}
