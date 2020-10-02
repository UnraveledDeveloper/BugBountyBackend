package dev.cuny.security.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import java.security.Key;

/**
 * @author William Gentry
 */
@Service
public class DefaultTokenManager extends AbstractTokenManager {

  public DefaultTokenManager() {
    super();
  }

  public DefaultTokenManager(Key signingKey, SignatureAlgorithm signatureAlgorithm) {
    super(signingKey, signatureAlgorithm);
  }
}
