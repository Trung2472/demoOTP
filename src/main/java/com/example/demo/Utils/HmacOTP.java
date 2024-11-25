package com.example.demo.Utils;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.SecureRandom;

public class HmacOTP {
    public static final String HMAC_SHA1 = "HmacSHA1";
    public static final String HMAC_SHA256 = "HmacSHA256";
    public static final String HMAC_SHA512 = "HmacSHA512";
    public static final String DEFAULT_ALGORITHM = "HmacSHA1";
    public static final int DEFAULT_NUMBER_DIGITS = 6;
    private static final int[] DIGITS_POWER = new int[]{1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
    protected final String algorithm;
    protected final int numberDigits;
    protected final int lookAroundWindow;

    public HmacOTP(int numberDigits, String algorithm, int delayWindow) {
        this.numberDigits = numberDigits;
        this.algorithm = algorithm;
        this.lookAroundWindow = delayWindow;
    }

    public static String generateSecret(int length) {
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1234567890";
        SecureRandom r = new SecureRandom();
        StringBuilder sb = new StringBuilder();

        for(int i = 0; i < length; ++i) {
            char c = chars.charAt(r.nextInt(chars.length()));
            sb.append(c);
        }

        return sb.toString();
    }

    public String generateHOTP(byte[] key, int counter) {
        String steps;
        for(steps = Integer.toHexString(counter).toUpperCase(); steps.length() < 16; steps = "0" + steps) {
        }

        return this.generateOTP(key, steps, this.numberDigits, this.algorithm);
    }

    public String generateHOTP(String key, int counter) {
        return this.generateHOTP(key.getBytes(), counter);
    }

    public int validateHOTP(String token, byte[] key, int counter) {
        for(int newCounter = counter; newCounter <= counter + this.lookAroundWindow; ++newCounter) {
            String candidate = this.generateHOTP(key, newCounter);
            if (candidate.equals(token)) {
                return newCounter + 1;
            }
        }

        return -1;
    }

    public int validateHOTP(String token, String key, int counter) {
        return this.validateHOTP(token, key.getBytes(), counter);
    }

    public String generateOTP(byte[] key, String counter, int returnDigits, String crypto) {
        String result;
        for(result = null; counter.length() < 16; counter = "0" + counter) {
        }

        byte[] msg = this.hexStr2Bytes(counter);
        byte[] hash = this.hmac_sha1(crypto, key, msg);
        int offset = hash[hash.length - 1] & 15;
        int binary = (hash[offset] & 127) << 24 | (hash[offset + 1] & 255) << 16 | (hash[offset + 2] & 255) << 8 | hash[offset + 3] & 255;
        int otp = binary % DIGITS_POWER[returnDigits];

        for(result = Integer.toString(otp); result.length() < returnDigits; result = "0" + result) {
        }

        return result;
    }

    private byte[] hmac_sha1(String crypto, byte[] keyBytes, byte[] text) {
        try {
            Mac hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            byte[] value = hmac.doFinal(text);
            return value;
        } catch (Exception var7) {
            Exception e = var7;
            throw new RuntimeException(e);
        }
    }

    private byte[] hexStr2Bytes(String hex) {
        byte[] bArray = (new BigInteger("10" + hex, 16)).toByteArray();
        byte[] ret = new byte[bArray.length - 1];
        System.arraycopy(bArray, 1, ret, 0, ret.length);
        return ret;
    }
}
