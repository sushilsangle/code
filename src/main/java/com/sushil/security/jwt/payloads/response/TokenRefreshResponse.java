package com.sushil.security.jwt.payloads.response;

public class TokenRefreshResponse {

    private String accessToken;
    private String freshToken;
    private String tokenType="Bearer";

    public TokenRefreshResponse(String accessToken, String freshToken) {
        this.accessToken = accessToken;
        this.freshToken = freshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getFreshToken() {
        return freshToken;
    }

    public void setFreshToken(String freshToken) {
        this.freshToken = freshToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }
}
