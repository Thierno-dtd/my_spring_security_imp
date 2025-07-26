package com.example.security.auth;

import com.example.security.configuraton.JwtService;
import com.example.security.constants.TypeRoles;
import com.example.security.entites.User;
import com.example.security.repositories.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AuthenticationService {

    @Value("${jwt.expiration}")
    private String jwtExpiration;

    @Value("${jwt.token-type}")
    private String tokenType;

    private final UserRepository utilisateurRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthenticationService(UserRepository utilisateurRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.utilisateurRepository = utilisateurRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationResponse register(RegisterRequest request) {
        var user= User.builder()
                .name(request.getPname())
                .pname(request.getPname())
                .email(request.getEmail())
                .passwd(passwordEncoder.encode(request.getPasswd()))
                .roles(TypeRoles.USER)
                .build();

        utilisateurRepository.save(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        var jwtToken=jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .expiresIn(Long.valueOf(jwtExpiration))
                .tokenType(tokenType)
                .build();
    }

    public AuthenticationResponse registerAdmin(RegisterRequest request) {
        var user= User.builder()
                .name(request.getName())
                .pname(request.getPname())
                .email(request.getEmail())
                .passwd(passwordEncoder.encode(request.getPasswd()))
                .roles(TypeRoles.ADMIN)
                .build();

        utilisateurRepository.save(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        var jwtToken=jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .expiresIn(Long.valueOf(jwtExpiration))
                .tokenType(tokenType)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        log.info("Tentative de connexion pour l'email: {}", request.getEmail());

        try {
            UserDetails user = utilisateurRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new EntityNotFoundException("aucun utilisateur n'est trouvé!"));

            if(passwordEncoder.matches(request.getPassword(), user.getPassword())){
                String jwtToken = jwtService.generateToken(user);
                String refreshToken = jwtService.generateRefreshToken(user);

                log.info("Connexion réussie pour l'email: {}", request.getEmail());

                return AuthenticationResponse.builder()
                        .token(jwtToken)
                        .refreshToken(refreshToken)
                        .expiresIn(Long.valueOf(jwtExpiration))
                        .tokenType(tokenType)
                        .build();
            } else {
                log.warn("Échec de connexion - mot de passe incorrect pour l'email: {}", request.getEmail());
                throw new EntityNotFoundException("Identifiants invalides");
            }
        } catch (Exception e) {
            log.warn("Échec de connexion pour l'email: {}", request.getEmail());
            throw e;
        }
    }

    public AuthenticationResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        String userEmail = jwtService.extractuserEmail(refreshToken);

        UserDetails user = utilisateurRepository.findByEmail(userEmail)
                .orElseThrow(() -> new EntityNotFoundException("Utilisateur non trouvé"));

        String newAccessToken = jwtService.refreshAccessToken(refreshToken, user);

        return AuthenticationResponse.builder()
                .token(newAccessToken)
                .refreshToken(refreshToken)
                .expiresIn(Long.valueOf(jwtExpiration))
                .tokenType(tokenType)
                .build();
    }

    public void logout(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            jwtService.blacklistToken(token);
            log.info("Utilisateur déconnecté, token blacklisté");
        } else {
            log.warn("Tentative de logout avec un header Authorization invalide");
            throw new IllegalArgumentException("Header Authorization invalide");
        }
    }
}
