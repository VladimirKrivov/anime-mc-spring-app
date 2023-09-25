package pro.gravit.simplecabinet.web.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import pro.gravit.simplecabinet.web.configuration.jwt.JwtFilter;

import java.util.Arrays;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private JwtFilter jwtFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .cors() // Enable CORS configuration
                .configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
                    config.setAllowedMethods(Arrays.asList("GET", "POST"));
                    config.setAllowedHeaders(Arrays.asList("Content-Type", "Authorization"));
                    config.setAllowCredentials(true);
                    return config;
                })
                .and()
                .authorizeRequests()
                .antMatchers("/admin/").hasRole("ADMIN")
                .antMatchers("/cabinet/").authenticated()
                .anyRequest().permitAll()
                .and()
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }
}







//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.cors().and()
////                .httpBasic().disable()
//                .csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .authorizeRequests()
//                .antMatchers("/admin/**").hasRole("ADMIN")
//                .antMatchers("/cabinet/**").authenticated()
//                .anyRequest().permitAll()
//                .and()
//                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
//    }
//
//    @Bean
//    CorsConfigurationSource corsConfigurationSource() {
//        CorsConfiguration configuration = new CorsConfiguration();
//        configuration.addAllowedOriginPattern(CorsConfiguration.ALL);
//        configuration.addAllowedOrigin("http://localhost:3000/");
//        configuration.setAllowedMethods(List.of("POST","PUT", "GET", "DELETE"));
//        configuration.setAllowedHeaders(List.of("Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization"));
//        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//        source.registerCorsConfiguration("/**", configuration);
//        return source;
//    }







