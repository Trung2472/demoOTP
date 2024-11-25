package com.example.demo.controller;

import com.example.demo.model.RegistrationTotpResponse;
import com.example.demo.service.HOTPService;
import com.example.demo.service.QRCodeService;
import com.example.demo.service.TOTPService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class UserController {

    private final TOTPService totpService;
    private final QRCodeService qrCodeService;

    // API để người dùng đăng ký tài khoản và tạo mã QR TOTP
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestParam String username) throws Exception {
        String secret = totpService.generateSecretKey();
        String totpUrl = totpService.getTOTPUrl(username, secret, "iTech");

        // Tạo mã QR từ URL
        String qrCodeImagePath = qrCodeService.generateQRCodeImage(totpUrl, 250, 250);

        return ResponseEntity.ok(new RegistrationTotpResponse(secret, qrCodeImagePath));
    }

    @PostMapping("/register-file")
    public ResponseEntity<?> register(@RequestParam String username) throws Exception {
        String secret = totpService.generateSecretKey();
        String totpUrl = totpService.getTOTPUrl(username, secret, "iTech");

        // Tạo mã QR từ URL
        byte[] array = qrCodeService.generateQRCodeImageToByte(totpUrl, 250, 250);
        ByteArrayResource resource = new ByteArrayResource(array);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(resource.contentLength())
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(username + "-qr-authenticator.png").build().toString())
                .body(resource);
    }

    // API để xác thực mã OTP người dùng nhập vào
    @PostMapping("/verify")
    public ResponseEntity<?> verifyOTP(@RequestParam String username, @RequestParam String otp) {
        boolean isValid = totpService.verifyTOTP(username, otp);

        if (isValid) {
            return ResponseEntity.ok("Xác thực thành công!");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Mã OTP không hợp lệ.");
        }
    }

    ///HTOP
    private final HOTPService hotpService;
    // API để người dùng đăng ký tài khoản và tạo mã QR TOTP
    @PostMapping("hotp/register")
    public ResponseEntity<?> registerUserHOTP(@RequestParam String username, @RequestParam Integer counter) throws Exception {
        String secret = hotpService.generateSecretKey();
        String totpUrl = hotpService.getTOTPUrl(username,  "iTech", secret, counter);

        // Tạo mã QR từ URL
        String qrCodeImagePath = qrCodeService.generateQRCodeImage(totpUrl, 250, 250);

        return ResponseEntity.ok(new RegistrationTotpResponse(secret, qrCodeImagePath));
    }

    @PostMapping("hotp/register-file")
    public ResponseEntity<?> registerHOTP(@RequestParam String username, @RequestParam Integer counter) throws Exception {
        String secret = hotpService.generateSecretKey();
        String totpUrl = hotpService.getTOTPUrl(username, "iTech", secret, counter);

        // Tạo mã QR từ URL
        byte[] array = qrCodeService.generateQRCodeImageToByte(totpUrl, 250, 250);
        ByteArrayResource resource = new ByteArrayResource(array);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(resource.contentLength())
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment().filename(username + "-qr-authenticator.png").build().toString())
                .body(resource);
    }

    // API để xác thực mã HOTP người dùng nhập vào
    @PostMapping("hotp/verify")
    public ResponseEntity<?> verifyHOTP(@RequestParam String username, @RequestParam String otp
            , @RequestParam Integer counter) {
        boolean isValid = hotpService.verifyTOTP(username, otp, counter);

        if (isValid) {
            return ResponseEntity.ok("Xác thực thành công!");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Mã HOTP không hợp lệ.");
        }
    }
}
