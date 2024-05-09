package com.abdohalim.springbootsecurity.SpringSecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.stream.Collectors;

@RestController
public class JwtAuthenticationResource {

    private JwtEncoder jwtEncoder;


    public JwtAuthenticationResource(JwtEncoder jwtEncoder) {

        this.jwtEncoder = jwtEncoder;
    }

    @GetMapping("/auth")
    public Authentication authentication(Authentication authentication){
        return  authentication;
    }
    @PostMapping("/authentication")
    public JwtRespose auth(Authentication authentication) {
        // Assuming you have logic to generate a JWT token based on the authentication information
        return new JwtRespose(generateToken(authentication));
    }

    private String generateToken(Authentication authentication) {
        var clams= JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60*30))
                .subject(authentication.getName())
                .claim("scomp",CrateScompe(authentication))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(clams)).getTokenValue();
    }
    private String CrateScompe(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(a->a.getAuthority()).collect(Collectors.joining(" "));
    }
}
record JwtRespose(String Token){}