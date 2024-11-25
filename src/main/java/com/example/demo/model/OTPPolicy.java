package com.example.demo.model;

import com.example.demo.Utils.Base32;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OTPPolicy implements Serializable {
    private static final Logger logger = LoggerFactory.getLogger(OTPPolicy.class);
    public static final boolean DEFAULT_IS_REUSABLE = false;
    private static final Map<String, String> algToKeyUriAlg = new HashMap<>();
    public static final String REALM_REUSABLE_CODE_ATTRIBUTE = "realmReusableOtpCode";
    public static final String HOTP = "hotp";
    public static final String TOTP = "totp";

    private String type;
    private String algorithm;
    private int initialCounter;
    private int digits;
    private int lookAheadWindow;
    private int period;
    private boolean isCodeReusable;
    public static OTPPolicy DEFAULT_POLICY;


    public OTPPolicy(String type, String algorithm, int initialCounter, int digits, int lookAheadWindow, int period) {
        this(type, algorithm, initialCounter, digits, lookAheadWindow, period, false);
    }
    public String getAlgorithmKey() {
        return algToKeyUriAlg.containsKey(this.algorithm) ? algToKeyUriAlg.get(this.algorithm) : this.algorithm;
    }

    public String getKeyURI(String displayName, String user, String secret) {
        String issuerName = URLEncoder.encode(displayName, StandardCharsets.UTF_8).replaceAll("\\+", "%20");
        String accountName = URLEncoder.encode(user, StandardCharsets.UTF_8);
//        String label = issuerName + ":" + accountName;
        String var10000 = Base32.encode(secret.getBytes());
        String parameters = "secret=" + var10000 + "&digits=" + this.digits + "&algorithm=" + algToKeyUriAlg.get(this.algorithm) + "&issuer=" + issuerName;
        if (this.type.equals(HOTP)) {
            parameters = parameters + "&counter=" + this.initialCounter;
        } else if (this.type.equals(TOTP)) {
            parameters = parameters + "&period=" + this.period;
        }

        return "otpauth://" + this.type + "/" + accountName + "?" + parameters;
    }

    static {
        algToKeyUriAlg.put("HmacSHA1", "SHA1");
        algToKeyUriAlg.put("HmacSHA256", "SHA256");
        algToKeyUriAlg.put("HmacSHA512", "SHA512");
        DEFAULT_POLICY = new OTPPolicy("totp", "HmacSHA1", 1, 6, 1, 30);
    }
}