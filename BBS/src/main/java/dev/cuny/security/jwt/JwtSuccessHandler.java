package dev.cuny.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.cuny.entities.Client;
import dev.cuny.repositories.ClientRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author William Gentry
 */
public class JwtSuccessHandler implements AuthenticationSuccessHandler {

  private final TokenSigner tokenSigner;
  private final ClientRepository clientRepository;
  private final ObjectMapper mapper;
  private final Logger logger = LoggerFactory.getLogger(getClass());

  public JwtSuccessHandler(TokenSigner tokenSigner, ClientRepository clientRepository, ObjectMapper mapper) {
    this.tokenSigner = tokenSigner;
    this.clientRepository = clientRepository;
    this.mapper = mapper;
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    final String token = tokenSigner.sign(authentication);
    response.addHeader(HttpHeaders.AUTHORIZATION, token);
    logger.info("Found authentication: {}", authentication);
    final Client client = clientRepository.findByEmail(authentication.getName());
    logger.info("Found client: {}", client);
    response.getOutputStream().write(mapper.writeValueAsBytes(client));
  }
}
