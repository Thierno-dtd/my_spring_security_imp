package com.example.security.configuraton;

import com.example.security.entites.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@Slf4j
public class JwtService {
    @Value("${jwt.secret}")
    private String SECRET_KEY;

    @Value("${jwt.expiration}")
    private String jwtExpiration;

    @Value("${jwt.refresh-expiration}")
    private String refreshExpiration;

    // AJOUTER : Blacklist des tokens révoqués (en production, utilisez Redis)
    private final Set<String> tokenBlacklist = ConcurrentHashMap.newKeySet();

    public String extractuserEmail(String token){
        return extractClaim(token, Claims::getSubject);
    }

    // AJOUTER : Extraction des rôles
    public List<String> extractRoles(String token) {
        return extractClaim(token, claims -> (List<String>) claims.get("roles"));
    }

    // AJOUTER : Extraction de l'ID utilisateur
    public Integer extractUserId(String token) {
        return extractClaim(token, claims -> (Integer) claims.get("userId"));
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims=extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        Map<String, Object> extraClaims = new HashMap<>();

        // AJOUTER : Inclure les rôles dans le token
        extraClaims.put("roles", userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));

        // AJOUTER : Inclure l'ID utilisateur si disponible
        if (userDetails instanceof User) {
            extraClaims.put("userId", ((User) userDetails).getId());
        }

        return generateToken(extraClaims, userDetails);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("type", "refresh");

        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + Long.valueOf(refreshExpiration) * 1000))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // MODIFIER : Validation avec blacklist
    public boolean isTokenValid(String token, UserDetails userDetails){
        try {
            // Vérifier si le token est blacklisté
            if (isTokenBlacklisted(token)) {
                log.warn("Tentative d'utilisation d'un token blacklisté");
                return false;
            }

            final String username = extractuserEmail(token);
            boolean isValid = (username.equals(userDetails.getUsername())) && !isTokenExpired(token);

            if (!isValid) {
                log.warn("Token invalide pour l'utilisateur: {}", username);
            }

            return isValid;
        } catch (Exception e) {
            log.error("Erreur lors de la validation du token: {}", e.getMessage());
            return false;
        }
    }

    // AJOUTER : Vérification si refresh token
    public boolean isRefreshToken(String token) {
        try {
            String tokenType = extractClaim(token, claims -> (String) claims.get("type"));
            return "refresh".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    // AJOUTER : Validation du refresh token
    public boolean isRefreshTokenValid(String refreshToken, UserDetails userDetails) {
        try {
            if (isTokenBlacklisted(refreshToken)) {
                return false;
            }

            if (!isRefreshToken(refreshToken)) {
                return false;
            }

            final String username = extractuserEmail(refreshToken);
            return (username.equals(userDetails.getUsername())) && !isTokenExpired(refreshToken);
        } catch (Exception e) {
            log.error("Erreur lors de la validation du refresh token: {}", e.getMessage());
            return false;
        }
    }

    // AJOUTER : Renouvellement de token avec refresh token
    public String refreshAccessToken(String refreshToken, UserDetails userDetails) {
        if (!isRefreshTokenValid(refreshToken, userDetails)) {
            throw new RuntimeException("Refresh token invalide");
        }

        log.info("Renouvellement du token pour l'utilisateur: {}", userDetails.getUsername());
        return generateToken(userDetails);
    }

    // AJOUTER : Blacklister un token (déconnexion)
    public void blacklistToken(String token) {
        tokenBlacklist.add(token);
        log.info("Token ajouté à la blacklist");
    }

    // AJOUTER : Vérifier si token blacklisté
    public boolean isTokenBlacklisted(String token) {
        return tokenBlacklist.contains(token);
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }

    public String generateToken(Map<String, Object> extractClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + Long.valueOf(jwtExpiration) * 1000))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // MODIFIER : Gestion d'erreurs robuste
    private Claims extractAllClaims(String token){
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.warn("Token expiré: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            log.error("Token JWT non supporté: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            log.error("Token JWT malformé: {}", e.getMessage());
            throw e;
        } catch (SignatureException e) {
            log.error("Signature JWT invalide: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            log.error("Token JWT vide: {}", e.getMessage());
            throw e;
        }
    }

    private Key getSignInKey(){
        try {
            byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (Exception e) {
            log.error("Erreur lors de la création de la clé de signature: {}", e.getMessage());
            throw new RuntimeException("Impossible de créer la clé JWT", e);
        }
    }
}