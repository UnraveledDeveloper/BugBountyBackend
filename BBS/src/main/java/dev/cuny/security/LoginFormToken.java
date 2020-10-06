package dev.cuny.security;

import dev.cuny.dtos.LoginFormDto;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * @author William Gentry
 */
public class LoginFormToken extends UsernamePasswordAuthenticationToken {

  public LoginFormToken(LoginFormDto dto) {
    super(dto.getEmail(), dto.getPassword());
  }
}
