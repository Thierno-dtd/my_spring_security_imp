package com.example.security.auth;


import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import static com.example.security.constants.utils.APP_ROOT;

@RestController
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
@RequestMapping(APP_ROOT+"/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping(value = "/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping(value = "/registerUser")
    public ResponseEntity<AuthenticationResponse> registerUer(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping(value = "/registerAdmin")
    public ResponseEntity<AuthenticationResponse> registerAdmin(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authenticationService.registerAdmin(request));
    }

    @PostMapping(value = "/refresh")
    public ResponseEntity<AuthenticationResponse> refreshToken(@RequestBody RefreshTokenRequest request){
        return ResponseEntity.ok(authenticationService.refreshToken(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || authHeader.isEmpty()) {
            return ResponseEntity.badRequest().body("Token d'autorisation manquant");
        }

        authenticationService.logout(authHeader);
        return ResponseEntity.ok().body(Map.of("message", "Déconnexion réussie"));
    }
}