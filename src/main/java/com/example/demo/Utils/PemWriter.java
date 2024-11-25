package com.example.demo.Utils;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

@SuppressWarnings({"unused"})
public class PemWriter extends BufferedWriter {

    public record PemType() {
        public static final String PRIVATE_KEY = "PRIVATE KEY";
        public static final String PUBLIC_KEY = "PUBLIC KEY";
    }
    private static final int LINE_LENGTH = 64;
    private final char[] buf = new char[LINE_LENGTH];
    public final static String BEGIN_FORMAT = "-----BEGIN %s-----";
    public final static String END_FORMAT = "-----END %s-----";

    public PemWriter(Writer var1) {
        super(var1);
    }

    public void writePrivateKey(byte[] content) throws IOException {
        this.writeObject(PemType.PRIVATE_KEY, Collections.emptyMap(), content);
    }

    public void writePublicKey(byte[] content) throws IOException {
        this.writeObject(PemType.PUBLIC_KEY, Collections.emptyMap(), content);
    }

    public void writeObject(String type, byte[] content) throws IOException {
        this.writeObject(type, Collections.emptyMap(), content);
    }
    public void writeObject(String type, Map<String, String> headers, byte[] content) throws IOException {
        this.writePreEncapsulationBoundary(type);
        if (!headers.isEmpty()) {
            for (Map.Entry<String, String> o : headers.entrySet()) {
                this.write(o.getKey() + ": " + o.getValue());
                this.newLine();
            }
            this.newLine();
        }
        this.writeEncoded(content);
        this.writePostEncapsulationBoundary(type);
    }

    private void writeEncoded(byte[] var1) throws IOException {
        String var2 = Base64.getEncoder().encodeToString(var1);
        this.write(var2, 0, var1.length);
        this.newLine();
    }

    public static String formatBegin(String var1) {
        return String.format(BEGIN_FORMAT, var1);
    }

    public static String formatEnd(String var1) {
        return String.format(END_FORMAT, var1);
    }

    public void writePreEncapsulationBoundary(String var1) throws IOException {
        this.write(formatBegin(var1));
        this.newLine();
    }

    public void writePostEncapsulationBoundary(String var1) throws IOException {
        this.write(formatEnd(var1));
        this.newLine();
    }
}
