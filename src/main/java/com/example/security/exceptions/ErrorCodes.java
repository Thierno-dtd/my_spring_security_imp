package com.example.security.exceptions;

public enum ErrorCodes {
    User_Not_Found(100),
    User_Not_Valid(101);

    private int code;
    ErrorCodes(int code) { this.code = code;}

    public int getCode() {
        return code;
    }
}
