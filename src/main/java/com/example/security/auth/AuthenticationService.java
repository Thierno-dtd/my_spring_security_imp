package com.example.security.auth;

import com.example.security.configuraton.JwtService;
import com.example.security.constants.TypeRoles;
import com.example.security.entites.User;
import com.example.security.repositories.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@Slf4j
public class AuthenticationService {
    private final UserRepository utilisateurRepository;

    @Autowired
    public AuthenticationService(UserRepository utilisateurRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.utilisateurRepository = utilisateurRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    private PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request) {
        var user= User.builder()
                .name(request.getPname())
                .pname(request.getPname())
                .email(request.getEmail())
                .passwd(passwordEncoder.encode(request.getPasswd()))
                .roles(TypeRoles.USER)
                .build();
        utilisateurRepository.save(user);
        var jwtToken=jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
    public AuthenticationResponse registerAdmin(RegisterRequest request) {
        var user= User.builder()
                .name(request.getPname())
                .pname(request.getPname())
                .email(request.getEmail())
                .passwd(passwordEncoder.encode(request.getPasswd()))
                .roles(TypeRoles.ADMIN)
                .build();
        utilisateurRepository.save(user);
        var jwtToken=jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        UserDetails user=utilisateurRepository.findByEmail(request.getEmail()).orElseThrow(()-> new EntityNotFoundException("aucun utilisateur n'est trouvé!"));
        String jwtToken="";
        if(passwordEncoder.matches(request.getPassword(),user.getPassword())){
            jwtToken=jwtService.generateToken(user);
        }

        UserDetails user1=utilisateurRepository.findByEmail(request.getEmail()).orElseThrow(()-> new EntityNotFoundException("aucun utilisateur n'est trouvé!"));
        if(!StringUtils.hasLength(user1.getUsername())){
            log.warn("le username de ce utilisateur est nul");
        }

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
