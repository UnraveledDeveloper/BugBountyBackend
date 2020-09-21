package dev.cuny.repotests;

import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.transaction.annotation.Transactional;

import dev.cuny.dtos.EmailDto;

@SpringBootTest
@ContextConfiguration(classes = dev.cuny.app.BbsApplication.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Transactional
class EmailDTOTests {


	@Test
	@Order(1)
	void testConstructEmail() {
		EmailDto edto = new EmailDto();
		
		edto.setEmail("test123@gmail.com");
		edto.setUsername("testclient");
		String estr = edto.toString();
		Assertions.assertEquals("EmailDto [username=testclient, email=test123@gmail.com]", estr);
	}

}
