package dev.cuny.repotests;


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.transaction.annotation.Transactional;

import dev.cuny.entities.ResetPassword;
import dev.cuny.repositories.ResetPasswordRepository;

@SpringBootTest
@ContextConfiguration(classes=dev.cuny.app.BbsApplication.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Transactional
class ResetPasswordRepoTests {

	@Autowired
	ResetPasswordRepository rpr;
	
	@Test
	@Order(1)
	void testResetPassword() {
		ResetPassword rp = new ResetPassword();
		rp.setId(25);
		rp.setemail("testemail@gmail.com");
		rp.setUsername("testusername");
		
		rp.setApiKey("123");
		
		rp.toString();
		
		rpr.save(rp);
		
		Assertions.assertNotEquals(0, rp.getId());
	}
}
