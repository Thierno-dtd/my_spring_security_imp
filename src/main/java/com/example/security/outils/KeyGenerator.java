package com.example.security.outils;

import org.springframework.security.crypto.codec.Hex;

import java.security.SecureRandom;

public class KeyGenerator {
    public static void main(String[] args) {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[64];
        random.nextBytes(key);
        System.out.println(Hex.encode(key));
    }
}
