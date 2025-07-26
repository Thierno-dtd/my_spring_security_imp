package com.example.security.outils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;

@Component
public class DataEncryption {

    @Value("${app.encryption.key}")
    private String encryptionKey;

    public String encryptSensitiveData(String data) {
        if (data == null || data.isEmpty()) return data;

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(getFixedKey(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            byte[] encrypted = cipher.doFinal(data.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            System.err.println("❌ Erreur de chiffrement: " + e.getMessage());
            return data;
        }
    }

    public String decryptSensitiveData(String encryptedData) {
        if (encryptedData == null || encryptedData.isEmpty()) return encryptedData;

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(getFixedKey(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            System.err.println("❌ Erreur de déchiffrement: " + e.getMessage());
            return encryptedData;
        }
    }

    private byte[] getFixedKey() {
        byte[] key = encryptionKey.getBytes();
        return Arrays.copyOf(key, 16);
    }
}
