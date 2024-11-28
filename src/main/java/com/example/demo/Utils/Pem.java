package com.example.demo.Utils;

import lombok.Builder;
import lombok.Data;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

@SuppressWarnings({"unused"})
public class Pem extends BufferedWriter {
    @Builder
    @Data
    public static class PemObject {
        String type;
        Map<String, String> headers;
        byte[] content;
    }
    public record PemType() {
        public static final String PRIVATE_KEY = "PRIVATE KEY";
        public static final String PUBLIC_KEY = "PUBLIC KEY";
    }
    private static final int LINE_LENGTH = 64;
    private final char[] buf = new char[LINE_LENGTH];
    public final static String BEGIN_FORMAT_PREFIX = "-----BEGIN ";
    public final static String END_FORMAT_PREFIX = "-----END ";
    public final static String TYPE_FORMAT_SUFFIX = "%s-----";

    public Pem(Writer var1) {
        super(var1);
    }

    public void writePrivateKey(byte[] content) throws IOException {
        this.writeObject(PemObject.builder()
                .type(PemType.PRIVATE_KEY)
                .headers(Collections.emptyMap())
                .content(content).build());
    }

    public void writePublicKey(byte[] content) throws IOException {
        this.writeObject(PemObject.builder()
                .type(PemType.PUBLIC_KEY)
                .headers(Collections.emptyMap())
                .content(content).build());
    }

    public void writeObject(String type, byte[] content) throws IOException {
        this.writeObject(PemObject.builder()
                .type(type.toUpperCase())
                .headers(Collections.emptyMap())
                .content(content).build());
    }
    public void writeObject(final PemObject data) throws IOException {
        this.writePreEncapsulationBoundary(data.getType());
        if (!data.getHeaders().isEmpty()) {
            for (Map.Entry<String, String> o : data.getHeaders().entrySet()) {
                this.write(o.getKey() + ": " + o.getValue());
                this.newLine();
            }
            this.newLine();
        }
        this.writeEncoded(data.getContent());
        this.writePostEncapsulationBoundary(data.getType());
    }

    private void writeEncoded(byte[] var1) throws IOException {
        String var2 = Base64.getEncoder().encodeToString(var1);
        this.write(var2, 0, var1.length);
        this.newLine();
    }

    public static String formatBegin(String var1) {
        return String.format(BEGIN_FORMAT_PREFIX + TYPE_FORMAT_SUFFIX, var1);
    }

    public static String formatEnd(String var1) {
        return String.format(END_FORMAT_PREFIX + TYPE_FORMAT_SUFFIX, var1);
    }

    public void writePreEncapsulationBoundary(String var1) throws IOException {
        this.write(formatBegin(var1));
        this.newLine();
    }

    public void writePostEncapsulationBoundary(String var1) throws IOException {
        this.write(formatEnd(var1));
        this.newLine();
    }

    ///
    public static PemObject read(String type, String pemData) {
        final String replaceStr = "";
        final String space = " ";
        String standardKey = pemData
                .replace(formatBegin(type), replaceStr)
                .replace(formatEnd(type), replaceStr)
                .replaceAll(System.lineSeparator(), replaceStr)
                .replace(space, replaceStr)
                .trim();
        byte[] decoded = Base64.getDecoder().decode(standardKey);
        return PemObject.builder().content(decoded).build();
    }
}
