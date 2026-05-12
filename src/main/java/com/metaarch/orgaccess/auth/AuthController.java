package com.metaarch.orgaccess.auth;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
  private final AuthService authService;

  public AuthController(AuthService authService) {
    this.authService = authService;
  }

  @PostMapping("/login")
  public AuthResponse login(@RequestBody LoginRequest request) {
    return authService.authenticate(request);
  }

  @GetMapping("/validate")
  public AuthValidationResponse validate(Authentication authentication) {
    return authService.validationResponse(authentication);
  }

  @GetMapping("/me")
  public AuthValidationResponse me(Authentication authentication) {
    return authService.validationResponse(authentication);
  }
}
