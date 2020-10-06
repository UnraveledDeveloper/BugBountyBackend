package dev.cuny.security;

import dev.cuny.entities.Client;
import dev.cuny.repositories.ClientRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author William Gentry
 */
@Service
public class ClientUserDetailsService implements UserDetailsService {

  private final ClientRepository clientRepository;

  public ClientUserDetailsService(ClientRepository clientRepository) {
    this.clientRepository = clientRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
    Client client = clientRepository.findByEmail(s);
    return new ClientUserDetails(client);
  }
}
