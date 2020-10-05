package dev.cuny.security;

import dev.cuny.security.jwt.AbstractTokenManager;
import dev.cuny.security.jwt.TokenParser;
import org.apache.maven.shared.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author William Gentry
 */
public class JwtPresentFilter extends OncePerRequestFilter {

  private final TokenParser tokenParser;
  private final UserDetailsService clientUserDetailsService;
  private final Logger logger = LoggerFactory.getLogger(getClass());

  public JwtPresentFilter(TokenParser tokenParser, UserDetailsService clientUserDetailsService) {
    this.tokenParser = tokenParser;
    this.clientUserDetailsService = clientUserDetailsService;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    // Don't check for token when authenticating
    if (HttpMethod.POST.name().equals(request.getMethod()) && "/login".equals(request.getRequestURI())) {
      filterChain.doFilter(request, response);
      return;
    }
    logger.info("Incoming {} request to {}", request.getMethod(), request.getRequestURI());
    String header = request.getHeader(HttpHeaders.AUTHORIZATION);
    Authentication authentication = null;
    if (!StringUtils.isBlank(header)) {
      final String token = header.replace(AbstractTokenManager.TOKEN_HEADER_PREFIX, "");
      authentication = tokenParser.parse(token);
    }
    if (authentication != null) {
      UserDetails details = clientUserDetailsService.loadUserByUsername(authentication.getName());
      UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(details.getUsername(), details.getPassword(), details.getAuthorities());
      auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
      SecurityContextHolder.getContext().setAuthentication(auth);
      logger.info("Successfully set security context for {} request to {}", request.getMethod(), request.getRequestURI());
    }
    filterChain.doFilter(request, response);
  }
}
