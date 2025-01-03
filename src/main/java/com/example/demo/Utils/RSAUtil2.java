package com.example.demo.Utils;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static com.example.demo.Utils.CryptoUtil.generateOTP;
import static java.nio.charset.StandardCharsets.UTF_8;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RSAUtil2 {
    private static final Logger log = LoggerFactory.getLogger(RSAUtil2.class);

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
        byte[] decoded = Base64.getDecoder().decode(standardKey.getBytes(StandardCharsets.UTF_8));
        KeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
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
    public static String publicKey =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlynlQjAh2pzdHwSRHIZj+HeOf+lqiSeOmG69ah3RvwbcbkrvxzF5f8+FevIN/q8R17NoOiNpIMeHZAL1BDlHw2Hek66bycoYFWcOWykzBSOU4ccrG1dgX7gzLHCIGiR5dtG5UdwVJ1vff7YUmFcDjc97sA8elTv9pGqzlEFJLiN939IWk+2GK3wVtBXlfUBKf8b366I+PWqSUIPSHqWZkWSwkA5LbMbi2wUi/RpsyREZ4kToPM9FFGGoFyb7zCw6SBLjpJJLaZaUy/kfjHGObSBvIaguFO22s84DCcrZWlIRn9kgPuICrll8jm/yfvhQP42LooWkC114fUCTffjLAQIDAQAB";
    public static String privateKey =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC0gnFWUBgcdCTEPj1/enwkypF3h8nnFnHJQ7YAL+PZLTevX962zxV1cA2pqiYgPTo/6wqMpJ/DqjpPT1egmTaJW80cxiy/PKqt/+eH/dJdpbSr4sWDfJAIC4Z7sigu9x0M2YKvTQHJRJiu4LUw5mnQuUieJ2kDRfaIwf8RQMsGGWiuCmF2ObndSZUw2eOJl4PVnhG+QM4eF23NZSPCT2MLcNjZfHDM51zdmx+1avci7i46FE/FVqaHIrVq3vF4rrfjX3RYsvQkXc9QEsqKBa3f1vl7rj1pis6T60Lo8X5N8zBar5Rf3PZHxdWt/Gq4vUM49hwz6GKa8UuQ9DosAD7lAgMBAAECggEAITlTIAZc8bvE2qP0EMccG293Z89D77c3WUqPsKgf4WTLt4lHRlGGSxfFRAGvw8ZRNtuNlQZl648k7V0WrVYV7iFJ9u5Y5RgG+EC+Pk8PDbKGtw5luUZPglOQvKq1b7OHEsrkHVzoo8Fu8t0kLGx0dHjt70Ikt3gEoPZH+sZ4t9XcYkBDu7NmUziiCF9Zw6SbpKqNQj8k9jiZXHcs5i+QeVwlCDQ18+LHtMTi020j5QBZqpAbDg7LlxD+gJigeNAGGvGOMYcprfQYA/qKI1V8CnnXDXUqbANWyYPsuczzKvxdlpN/OKrvFsFae8ogzhcQi9TdHQzGATj8cf9xIMhgHwKBgQD5yox08wo4swhD5K2pFtMYuxvYe8PMnonWdAffny6SspzcQ0t4P2ZJ+seAWOuqA2bEXP3x2Y2Zb3G5IbC/XV+TXYj9yT02D5i2UDTCL7HORsgVVwl0d90qelxAknf0PVoy1Dug4PtH9doEe8t9Rc/dbtZiXYiSlYdENTATz0RmQwKBgQC4/wvqU8VhIG4MwiccWAo0FpbE2KmyVw8G/YArgCCTtw4Fz6sHz1UWayjyXh8c3AkHOM543tpt8hqe2b9WRYgw+H2RixzAO5daQg9fhzYUS4CBv3hQq7DJRlAhqGmJugS8pfpDkNUvlYRZ2LwSoyM/YOSBP6cA2CKyAuXsWwZ3twKBgQCO2XW/v+ndiQ01/oYNx/7LCt4ezJCp6RR8rvh9u0PgIwMvt9BmISO3NRJ4ZOHI5Y8UxvV3JOokkCYiMJEqrxRkaz5XnIlD7GFyCaZSUwJFLBdqlM7Ua2Pw0e8GAn1VEO0PWm4LT/6EJaYboEw8BPud76/sqv7ajWbA7AXlnkfIjwKBgGjfLMIJ+zq0R66z4bgPsLkWlSHCMXEIKVytGJuQZudWPnzM3QfwYSv0U6IR+VFC61tMuL+Mlgb92Fl01yLxB+O6+nQniITxQzvHdy+QVvfqVU84W9xfeDihw4tRDYMmEMlgzh6/XBs9h2nnk7Z9BN5I70DV9LZl0EVZnz393AzBAoGAGC5O2+s+lYocYs6ghakEocr0qMiWsj2CeymH81JomYrvSrcuj2V4iOK54T7xjqWsBzAvMT91HSs7kL/QdXrLfNmS54NUpwwbFpeCmgMWhxWeQ7APDpoAByryk+9upxLuiaLQBfhc5siCQ3eIAdg3km6YWtnaSwoMm6rN0JmSPtY=";


    public static void main(String[] args) throws Exception {
        GoogleAuthenticator gAuth = new GoogleAuthenticator();

        // Tạo khóa bí mật
        String keyPlainText = "This is sparta khlfjlgkhlkgjh jjglkjhitjh ỉmtmh lrmhiỏtihmrtihmktmrlkmhlr mhmtr lhmtrmhỏ mthmro pthpỏt mhrotmhoimr";
        System.out.println("Secret Key: " + keyPlainText);

        String signSecret = sign(keyPlainText, loadPrivateKey(privateKey));
        System.out.println("Sign Secret: " + signSecret);
        // Tạo mã OTP dựa trên TOTP
        int otp = gAuth.getTotpPassword(signSecret);
        System.out.println("Generated TOTP: " + otp);

        // Kiểm tra OTP với TOTP
        boolean isValid = gAuth.authorize(signSecret, otp);
        System.out.println("Is the TOTP valid? " + isValid);

        // HOTP Example: Kiểm tra mã HOTP dựa trên counter
        String counterStr = generateOTP(8);
        int counter = Integer.parseInt(counterStr);
        otp = gAuth.getTotpPassword(signSecret, counter);
        System.out.println("Generated HOTP for counter " + counterStr + ": " + otp);

        // Kiểm tra tính hợp lệ của HOTP
        isValid = gAuth.authorize(signSecret, otp, counter);
        System.out.println("Is the HOTP valid? " + isValid);


    }

    private void addKey() throws Exception {
        KeyPair keyPair = generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        String publicKeyStr = new String(Base64.getEncoder().encode(publicKey.getEncoded()), StandardCharsets.UTF_8);
        System.out.println("Public Key: " + publicKeyStr);
        RSAUtil2.publicKey = publicKeyStr;

        PrivateKey privateKey = keyPair.getPrivate();
        byte[] privateKeyByte = Base64.getEncoder().encode(privateKey.getEncoded());
        String privateKeyStr = new String(privateKeyByte, StandardCharsets.UTF_8);
        System.out.println("Private Key: \n" + privateKeyStr);
        String pemPK = RSAUtil2.privateKeyToPEM(privateKey);
        System.out.println("Private Key (pemPK): \n" + pemPK);
        RSAUtil2.privateKey = privateKeyStr;
    }
}
