package dev.cuny.security;

import dev.cuny.entities.Client;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author William Gentry
 */
public class ClientUserDetails implements UserDetails {

  private final Client client;

  public ClientUserDetails(Client client) {
    this.client = client;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return Collections.singleton(BugBountyRole.values()[client.getRole()]);
  }

  @Override
  public String getPassword() {
    return client.getPassword();
  }

  @Override
  public String getUsername() {
    return client.getEmail();
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}
