package tf.uiuc.spoink;

import com.mitchellbosecke.pebble.PebbleEngine;
import com.mitchellbosecke.pebble.loader.Loader;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;


@SpringBootApplication
public class SpoinkApplication {
	public static void main(String[] args) {
		SpringApplication.run(SpoinkApplication.class);
	}
	@Bean
	public Loader<?> pebbleLoader() {
		return new PebbleEngine.Builder().build().getLoader();
	}
}
