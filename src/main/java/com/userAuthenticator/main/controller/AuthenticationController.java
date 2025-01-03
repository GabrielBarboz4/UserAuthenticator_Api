package com.userAuthenticator.main.controller;

import com.userAuthenticator.main.dto.LoginUserDto;
import com.userAuthenticator.main.dto.RegisterUserDto;
import com.userAuthenticator.main.dto.VerifyUserDto;
import com.userAuthenticator.main.model.User;
import com.userAuthenticator.main.responses.LoginResponse;
import com.userAuthenticator.main.service.AuthenticationService;
import com.userAuthenticator.main.service.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping( "/auth" )
@RestController
public class AuthenticationController {

    private final JwtService jwtService;

    private final AuthenticationService authenticationService;


    public AuthenticationController ( JwtService jwtService, AuthenticationService authenticationService ) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
    }

    @PostMapping( "/signup" )
    public ResponseEntity<User> register ( @RequestBody RegisterUserDto registerUserDto ) {
        User registerdUser = authenticationService.signup( registerUserDto );
        return ResponseEntity.ok( registerdUser );
    }

    @PostMapping( "/login" )
    public ResponseEntity<LoginResponse> authenticate (@RequestBody LoginUserDto loginUserDto ) {
        User authenticatedUser = authenticationService.authenticate( loginUserDto );
        String jtwToken = jwtService.generateToken(authenticatedUser);
        LoginResponse loginResponse = new LoginResponse(jtwToken, jwtService.getExpirationTime());
        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping( "/verify" )
    public ResponseEntity<?> verifyUser ( @RequestBody VerifyUserDto verifyUserDto ) {
        try {
            authenticationService.verifyUser(verifyUserDto);
            return ResponseEntity.ok("Account verified successfully");
        } catch ( RuntimeException e ) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping( "/resend" )
    public ResponseEntity<?> resendVerificationCode ( @RequestParam String email ) {
        try {
            authenticationService.resendVerificationCode( email );
            return ResponseEntity.ok("Verification code sent");
        } catch ( RuntimeException e ) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}