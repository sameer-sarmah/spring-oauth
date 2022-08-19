package northwind.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Import;

import northwind.config.AuthServerConfig;

@SpringBootApplication
@Import({AuthServerConfig.class})
public class AuthorizationServer extends SpringBootServletInitializer{
	
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
    	return application.sources(AuthorizationServer.class);
    }

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServer.class, args);
		System.err.println("##########AuthorizationServer#######");
	}
	
}
