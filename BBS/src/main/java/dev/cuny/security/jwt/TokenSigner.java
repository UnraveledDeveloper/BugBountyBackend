package dev.cuny.security.jwt;

import org.springframework.security.core.Authentication;

/**
 * @author William Gentry
 */
public interface TokenSigner {

  String sign(Authentication authentication);
}
