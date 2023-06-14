package com.example.green.stitch.GreenStitchAssignment.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class jwtService {

    private static final String Secret_Key = "aPj7NPtNyDnWUcf1nGoqkwOatO3+uPgb519jt8hkqoE=";

    //add jwt dependency to use jwt service.

    public String extractUserName(String jwtToken) {
        return extractClaim(jwtToken,Claims::getSubject);
    }

    private Claims extractAllClaims(String jwtToken)
    {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())    //to deode a token we need siging key.
                .build()
                .parseClaimsJws(jwtToken)
                .getBody(); //get all the token after parsing jwtToken.
    }

    public <T> T  extractClaim(String jwtToken, Function<Claims,T> claimResolver)
    {
        final Claims claims = extractAllClaims(jwtToken);
        return claimResolver.apply(claims);
    }

    public String generateToken(Map<String,Object> extractClaims, UserDetails userdetails)
    {
        return Jwts.builder()
                .setClaims(extractClaims)
                .setSubject(userdetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() +1000*60*24))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(UserDetails userdetails)
    {
        return generateToken(new HashMap<>(),userdetails);
    }

    public boolean isTokenValid(UserDetails userDetails, String jwtToken)
    {
        //check if the user and the token are for the same user.
        final String userName = extractUserName(jwtToken);
        return userName.equals(userDetails.getUsername()) && !isTokenExpired(jwtToken);
    }

    private boolean isTokenExpired(String jwtToken) {
        return extractExpirationDate(jwtToken).before(new Date());
    }

    private Date extractExpirationDate(String jwtToken) {
        return extractClaim(jwtToken,Claims::getExpiration);
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(Secret_Key);
        return Keys.hmacShaKeyFor(keyBytes); //algorithm
    }
}
