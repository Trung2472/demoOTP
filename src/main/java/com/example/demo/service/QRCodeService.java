package com.example.demo.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;

@Service
public class QRCodeService {

    public String generateQRCodeImage(String text, int width, int height) throws WriterException, IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height);

        String filePath = "C:/Users/demo/demo/qrcodes/" + System.currentTimeMillis() + "_totp.png";
        Path path = Path.of(filePath);
        // Tạo thư mục nếu chưa tồn tại
        try {
            Files.createDirectories(path.getParent());
        } catch (FileAlreadyExistsException e) {
            // Thư mục đã tồn tại, không cần làm gì
        }
        MatrixToImageWriter.writeToPath(bitMatrix, "PNG", path);
        return filePath;
    }

    public byte[] generateQRCodeImageToByte(String text, int width, int height) throws WriterException, IOException {
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(text, BarcodeFormat.QR_CODE, width, height);
        return convertBufferedImageToByteArray(MatrixToImageWriter.toBufferedImage(bitMatrix));
    }

    public static byte[] convertBufferedImageToByteArray(BufferedImage bufferedImage) throws IOException {
        // Tạo một ByteArrayOutputStream để chứa dữ liệu byte của ảnh
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        // Ghi hình ảnh vào ByteArrayOutputStream dưới định dạng "PNG" hoặc "JPEG"
        // Bạn có thể thay đổi định dạng tùy thuộc vào yêu cầu (ví dụ: "PNG", "JPEG")
        ImageIO.write(bufferedImage, "PNG", byteArrayOutputStream);

        // Trả về mảng byte
        return byteArrayOutputStream.toByteArray();
    }
}
