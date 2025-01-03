package com.example.demo.Utils;

import com.warrenstrange.googleauth.*;
import io.micrometer.common.util.StringUtils;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
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
import java.util.Formatter;
import java.util.Random;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RSAUtil {
    private static final Logger log = LoggerFactory.getLogger(RSAUtil.class);

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static PrivateKey loadPrivateKey(String privateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String standardKey = privateKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace(" ", "")
                .trim();
        log.debug("standard privateKey: {}", standardKey);
        byte[] decoded = Base64.decodeBase64(standardKey);
        KeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    public static String decrypt(String privateKey, String encryptedText)
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException,
                    BadPaddingException, InvalidKeyException {
        try {
            if (StringUtils.isNotEmpty(encryptedText)) {
                byte[] bytes = Base64.decodeBase64(encryptedText);
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
        try (Pem pem = new Pem(stringWriter)) {
            pem.writePrivateKey(privateKey.getEncoded());
        } catch (Exception e) {
            log.error("error when generate private key", e);
        }
        return stringWriter.toString();
    }
    // Hàm băm chuỗi đầu vào sử dụng SHA-256
    public static String getSHA256Hash(String input) {
        return bytesToHex(hashing(input, HashingAlgorithm.SHA_256));
    }

    // Hàm băm chuỗi đầu vào sử dụng SHA-256
    public static String getSHA1Hash(String input) {
        return bytesToHex(hashing(input, HashingAlgorithm.SHA_1));
    }

    public static byte[] hashing(String input, HashingAlgorithm hashingAlgorithm) {
        try {
            // Tạo đối tượng MessageDigest với thuật toán SHA1
            MessageDigest md = MessageDigest.getInstance(hashingAlgorithm.algorithm);

            // Băm chuỗi đầu vào (chuyển về dạng byte)
            return md.digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.error("error when generate hash", e);
            return new byte[0];
        }
    }

    // Hàm chuyển đổi mảng byte thành chuỗi hexa
    public static String bytesToHex(byte[] bytes) {
        Formatter formatter = new Formatter();
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    public static String encodeBaseN(KeyRepresentation keyRepresentation, byte[] secret) {
        return switch (keyRepresentation) {
            case BASE32 -> {
                Base32 codec32 = new Base32();
                yield codec32.encodeToString(secret);
            }
            case BASE64 -> {
                Base64 codec64 = new Base64();
                yield codec64.encodeToString(secret);
            }
        };
    }

    public static String hashingSecret(String secret) {
        byte[] hashingSecret = hashing(secret, HashingAlgorithm.SHA_256);
        return encodeBaseN(KeyRepresentation.BASE64, hashingSecret);
    }

    public static String hashingSecret(String secret, KeyRepresentation keyRepresentation) {
        byte[] hashingSecret = hashing(secret, HashingAlgorithm.SHA_256);
        return encodeBaseN(keyRepresentation, hashingSecret);
    }

    public static String hashingSecret(String secret, HashingAlgorithm hashingAlgorithm) {
        byte[] hashingSecret = hashing(secret, hashingAlgorithm);
        return encodeBaseN(KeyRepresentation.BASE64, hashingSecret);
    }

    public static String hashingSecret(String secret, KeyRepresentation keyRepresentation, HashingAlgorithm hashingAlgorithm) {
        byte[] hashingSecret = hashing(secret, hashingAlgorithm);
        return encodeBaseN(keyRepresentation, hashingSecret);
    }

    public static String generateNumberWithLength(int length) {
        // Tập hợp ký tự số từ 0-9
        String characters = "0123456789";
        Random random = new Random();
        StringBuilder otp = new StringBuilder();

        // Vòng lặp tạo
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            otp.append(characters.charAt(index));
        }

        return otp.toString();
    }

    public static void main(String[] args) {
        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder configBuilder
                = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder();
        configBuilder.setKeyRepresentation(KeyRepresentation.BASE64);
        GoogleAuthenticator gAuth = new GoogleAuthenticator(configBuilder.build());

        // Tạo khóa bí mật
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        System.out.println("Secret Key: " + key.getKey());
        String keySecret = hashingSecret("username");
        System.out.println("Secret Key: " + keySecret);


        // Tạo mã OTP dựa trên TOTP
        int otp = gAuth.getTotpPassword(keySecret);
        System.out.println("Generated TOTP: " + otp);

        // Kiểm tra OTP với TOTP
        boolean isValid = gAuth.authorize(keySecret, otp);
        System.out.println("Is the OTP valid? " + isValid);

        // HOTP Example: Kiểm tra mã HOTP dựa trên counter
        int counter = 154;
        otp = gAuth.getTotpPassword(keySecret, counter);
        System.out.println("Generated HOTP for counter " + counter + ": " + otp);

        // Kiểm tra tính hợp lệ của HOTP
        isValid = gAuth.authorize(keySecret, otp, counter);
        System.out.println("Is the HOTP valid? " + isValid);
    }

    @Getter
    public enum HashingAlgorithm {
        SHA_1("SHA-1"),
        SHA_256("SHA-256"),
        SHA_512("SHA-512"),
        ;
        private final String algorithm;

        // Constructor
        HashingAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }
        public static HashingAlgorithm of(HmacHashFunction algorithm) {
            switch (algorithm) {
                case HmacSHA1 -> {
                    return SHA_1;
                }
                case HmacSHA256 -> {
                    return SHA_256;
                }
                case HmacSHA512 -> {
                    return SHA_512;
                }
            }
            return SHA_1;
        }

    }
}
