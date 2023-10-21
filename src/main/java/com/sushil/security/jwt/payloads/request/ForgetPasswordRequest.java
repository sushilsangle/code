package com.sushil.security.jwt.payloads.request;

public class ForgetPasswordRequest {

    private String email;

    private  String mobileNumber;


    public ForgetPasswordRequest(String email, String mobileNumber) {
        this.email = email;
        this.mobileNumber = mobileNumber;
    }

    public String getMobileNumber() {
        return mobileNumber;
    }

    public void setMobileNumber(String mobileNumber) {
        this.mobileNumber = mobileNumber;
    }

    public ForgetPasswordRequest(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
