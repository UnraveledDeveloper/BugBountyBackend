package dev.cuny.security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @author William Gentry
 */
public interface TokenParser {

  Authentication parse(String token);
}
