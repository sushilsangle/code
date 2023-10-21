package com.sushil.security.jwt;

import com.sushil.security.services.UserDetailsImpl;
import com.sushil.security.services.UserDetailsServiceImpl;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtUtils.class);



    @Value("${bezkoder.app.jwtSecret}")
    private String jwtSecret;
    @Value("${bezkoder.app.jwtExpirationMs}")
    private int jwtExpirationMs;

   /* public String generateJwtToken(Authentication authentication){
        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();
        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime()+jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512,jwtSecret)
                .compact();
    }*/

    public String generateJwtToken(UserDetailsImpl userPrincipal){
        return generateTokenFromUsername(userPrincipal.getUsername());
    }
    public String generateTokenFromUsername(String username){
        return Jwts.builder().setSubject(username).setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime()+jwtExpirationMs)).signWith(SignatureAlgorithm.HS512,jwtSecret).compact();
    }
    public String getUserNameFromJwtToken(String token){
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJwt(token).getBody().getSubject();
    }
    public boolean validateJwtToken(String authToken){
        try
        {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;

        }catch (SignatureException se){
            LOGGER.error("Invalid JWT signature: {}",se.getMessage());
        }catch (MalformedJwtException me){
            LOGGER.error("Invalid JWT Token: {}",me.getMessage());
        }catch (ExpiredJwtException ee){
            LOGGER.error("JWT Token is expired: {}",ee.getMessage());
        }catch (UnsupportedJwtException ue){
            LOGGER.error("JWT Token is unsupported: {}",ue.getMessage());
        }catch (IllegalArgumentException ie){
            LOGGER.error("JWT claims string is empty: {}",ie.getMessage());
        }
        return false;
    }
}
