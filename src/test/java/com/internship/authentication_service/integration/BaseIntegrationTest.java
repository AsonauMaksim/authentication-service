package com.internship.authentication_service.integration;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import java.security.SecureRandom;
import java.util.Base64;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
public abstract class BaseIntegrationTest {

    private static final String POSTGRES_IMAGE = "postgres:16";

    protected static final PostgreSQLContainer<?> POSTGRES_CONTAINER =
            new PostgreSQLContainer<>(POSTGRES_IMAGE)
                    .withDatabaseName("auth_db_test")
                    .withUsername("postgres")
                    .withPassword("12345");

    static {
        POSTGRES_CONTAINER.start();
    }

    /** генерируем валидный base64-секрет для jjwt */
    private static String randomBase64Secret() {
        byte[] buf = new byte[64];
        new SecureRandom().nextBytes(buf);
        return Base64.getEncoder().encodeToString(buf);
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES_CONTAINER::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES_CONTAINER::getUsername);
        registry.add("spring.datasource.password", POSTGRES_CONTAINER::getPassword);

        registry.add("jwt.secret", BaseIntegrationTest::randomBase64Secret);
        registry.add("jwt.access-token-expiration-ms", () -> 3600000);
        registry.add("jwt.refresh-token-expiration-ms", () -> 604800000);
    }
}