package northwind.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Import;

import northwind.config.ResourceServerConfig;


@SpringBootApplication
@Import({ResourceServerConfig.class})
public class ResourceServer extends SpringBootServletInitializer{

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
    	return application.sources(ResourceServer.class);
    }
	
	public static void main(String[] args) {
		SpringApplication.run(ResourceServer.class, args);
		System.err.println("##########ResourceServer#######");
	}
	
}
