package org.bspv.edge;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

@EnableZuulProxy
@SpringBootApplication
public class BspvEdgeServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(BspvEdgeServiceApplication.class, args);
	}
}
