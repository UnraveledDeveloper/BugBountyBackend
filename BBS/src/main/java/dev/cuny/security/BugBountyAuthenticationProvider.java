package dev.cuny.security;

import org.apache.maven.shared.utils.StringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author William Gentry
 */
public class BugBountyAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

  private final UserDetailsService userDetailsService;
  private final PasswordEncoder passwordEncoder;

  public BugBountyAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
    this.userDetailsService = userDetailsService;
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {
    final String credentials = (String) usernamePasswordAuthenticationToken.getCredentials();
    if (StringUtils.isBlank(credentials) || !passwordEncoder.matches(credentials, userDetails.getPassword())) {
      throw new BadCredentialsException("Invalid credentials");
    }
  }

  @Override
  protected UserDetails retrieveUser(String s, UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {
    return userDetailsService.loadUserByUsername((String) usernamePasswordAuthenticationToken.getPrincipal());
  }
}
