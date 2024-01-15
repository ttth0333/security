package com.tringuyen.security.config;

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
public class JwtService {

    private static final String SECRET_KEY = "BD31DE0F25F917E3B7627B7A00FBBF58245E93A91214147D32954D29BE209560D9CE17F12E5F7153A3906FEB0CA2F0D0163A96EB963583488AF9792D6F705E8940165EABB3C4126CA4A67C03169994692FDC0B0AD327B3298B0B54AE046D5F6AFC312691DC5BBC35FF9DE03A4B5432B828B64A71D91D3A947DC3BBFE3304915D";
    public String extractUsername(String token) { //1
        return extractClaim(token, Claims::getSubject); // the subject should be a email-username
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) { //4
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) { //7
        return generateToken(new HashMap<>(), userDetails); // generate token from userdtail only
    }

    private String generateToken( //6
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts // => generate a token out of extraclaims and userdetail
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); // compact generate and return a token
    }

    public boolean isTokenValid(String token, UserDetails userDetails) { //8
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) { //2
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // SignInKey is used to create signature part of jwt -> verify sender of jwt is legit
    private Key getSignInKey() { //3
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
