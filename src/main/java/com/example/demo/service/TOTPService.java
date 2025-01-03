package com.example.demo.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class TOTPService {


    // Giả định một cơ sở dữ liệu tạm thời lưu trữ secret key của người dùng
    private final Map<String, String> userSecrets = new HashMap<>();

    // Sinh secret key cho người dùng
    public String generateSecretKey() {
        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder gAuthConfig = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder();
        gAuthConfig.setCodeDigits(8);
        GoogleAuthenticator gAuth = new GoogleAuthenticator(gAuthConfig.build());
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }

    // Tạo URL cho TOTP
    public String getTOTPUrl(String username, String secret, String issuer) {
        userSecrets.put(username, secret);  // Lưu secret key cho người dùng
//        OTPPolicy otpPolicy = OTPPolicy.DEFAULT_POLICY;
//        return otpPolicy.getKeyURI(issuer, username, secret);
        return String.format("otpauth://totp/%s?secret=%s&issuer=%s", username, secret, issuer);
    }

    // Xác thực mã OTP ,
    // windowSize = 1: Cho phép xác thực mã OTP của chu kỳ hiện tại và một chu kỳ trước hoặc sau.
    public boolean verifyTOTP(String username, String otp) {
        String secret = userSecrets.get(username);
        if (secret == null) return false;
        GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder gAuthConfig = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder();
        gAuthConfig.setCodeDigits(8);
        GoogleAuthenticator gAuth = new GoogleAuthenticator(gAuthConfig.build());
        return gAuth.authorize(secret, Integer.parseInt(otp));
    }


}