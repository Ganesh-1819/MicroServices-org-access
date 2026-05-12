package com.metaarch.orgaccess.security;

import java.util.List;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthUserDetailsService implements UserDetailsService {
  private final AuthProperties properties;
  private final PasswordEncoder passwordEncoder;

  public AuthUserDetailsService(AuthProperties properties, PasswordEncoder passwordEncoder) {
    this.properties = properties;
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    AuthProperties.User configuredUser = properties.getUsers()
      .stream()
      .filter(user -> user.getUsername().equals(username))
      .findFirst()
      .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

    List<SimpleGrantedAuthority> authorities = configuredUser.getRoles()
      .stream()
      .map(SimpleGrantedAuthority::new)
      .toList();

    return User.withUsername(configuredUser.getUsername())
      .password(passwordEncoder.encode(configuredUser.getPassword()))
      .authorities(authorities)
      .build();
  }
}
