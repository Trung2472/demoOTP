package com.example.demo.service;

public interface AuthenticationUser {
    default String registration(String userName) {

        return null;
    }

    default String generateOtp(String userName) {

        return null;
    }

    default boolean verifyOtp(String userName, String otp) {

        return false;
    }
}
