package com.example.demo.service;

import com.example.demo.model.OTPPolicy;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.KeyRepresentation;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class HOTPService {


    // Giả định một cơ sở dữ liệu tạm thời lưu trữ secret key của người dùng
    private final Map<String, String> userSecrets = new HashMap<>();

    // Sinh secret key cho người dùng
    public String generateSecretKey() {
        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder gAuthConfig = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder();
        gAuthConfig.setKeyRepresentation(KeyRepresentation.BASE64);
        GoogleAuthenticator gAuth = new GoogleAuthenticator(gAuthConfig.build());
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }

    // Tạo URL cho TOTP
    public String getTOTPUrl(String username, String issuer, String secret, int counter) {
        userSecrets.put(username, secret);  // Lưu secret key cho người dùng
        OTPPolicy otpPolicy = OTPPolicy.DEFAULT_POLICY;
        otpPolicy.setType(OTPPolicy.HOTP);
        otpPolicy.setInitialCounter(counter);
        return otpPolicy.getKeyURI(issuer, username, secret);
//        return String.format("otpauth://totp/%s?secret=%s&issuer=%s", username, secret, issuer);
    }

    // Xác thực mã OTP ,
    public boolean verifyTOTP(String username, String otp, int counter) {
        String secret = userSecrets.get(username);
        if (secret == null) return false;
        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder gAuthConfig = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder();
        gAuthConfig.setKeyRepresentation(KeyRepresentation.BASE64);
        GoogleAuthenticator gAuth = new GoogleAuthenticator(gAuthConfig.build());
        return gAuth.authorize(secret, Integer.parseInt(otp), counter);
    }


}