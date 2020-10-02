package dev.cuny.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.cuny.dtos.LoginFormDto;
import dev.cuny.repositories.ClientRepository;
import dev.cuny.security.jwt.JwtSuccessHandler;
import dev.cuny.security.jwt.TokenSigner;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author William Gentry
 */
public class LoginFilter extends AbstractAuthenticationProcessingFilter {

  private final ObjectMapper mapper;
  private final AuthenticationProvider authenticationProvider;

  protected LoginFilter(ObjectMapper mapper, AuthenticationProvider authenticationProvider, TokenSigner tokenSigner, ClientRepository clientRepository) {
    super(new AntPathRequestMatcher("/login", HttpMethod.POST.toString()));
    this.mapper = mapper;
    this.authenticationProvider = authenticationProvider;
    this.setAuthenticationSuccessHandler(new JwtSuccessHandler(tokenSigner, clientRepository, mapper));
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException, IOException, ServletException {
    LoginFormDto loginForm = mapper.readValue(req.getInputStream(), LoginFormDto.class);
    return authenticationProvider.authenticate(new LoginFormToken(loginForm));
  }
}
