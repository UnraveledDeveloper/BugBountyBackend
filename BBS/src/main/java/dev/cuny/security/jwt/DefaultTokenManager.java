package dev.cuny.security.jwt;

import org.springframework.stereotype.Service;

/**
 * @author William Gentry
 */
@Service
public class DefaultTokenManager extends AbstractTokenManager {

  private static final String signingKey = "BugBountyBugBountyBugBountyBugBountyBugBounty";

  public DefaultTokenManager() {
    super(signingKey);
  }
}
