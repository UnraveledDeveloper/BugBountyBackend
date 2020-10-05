package dev.cuny.security;

import org.springframework.security.core.GrantedAuthority;

/**
 * @author William Gentry
 */
public enum BugBountyRole implements GrantedAuthority {

  ROLE_UNREGISTERED("ROLE_UNREGISTERED"),

  ROLE_USER("ROLE_USER"),

  ROLE_ADMIN("ROLE_ADMIN");

  private final String authority;

  BugBountyRole(String authority) {
    this.authority = authority;
  }

  @Override
  public String getAuthority() {
    return authority;
  }
}
