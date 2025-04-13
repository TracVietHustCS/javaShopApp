package org.project1.shopweb.configure;

import lombok.RequiredArgsConstructor;
import org.project1.shopweb.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

        private final UserRepository userRepository;
        //user's detail object
        @Bean
        // khi click vao ham overwrite cua loaduserbyusername, no direct toi function nay
        public UserDetailsService userDetailsService() {
            return phoneNumber -> userRepository
                    .findByPhoneNumber(phoneNumber)
                    .orElseThrow(() ->
                            new UsernameNotFoundException(
                                    "Cannot find user with phone number = "+phoneNumber));
        }
        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
        @Bean
        public AuthenticationProvider authenticationProvider() {
            DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
            authProvider.setUserDetailsService(userDetailsService());
            authProvider.setPasswordEncoder(passwordEncoder());
            return authProvider;
        }
        @Bean
        public AuthenticationManager authenticationManager(
                AuthenticationConfiguration config
        ) throws Exception {
            return config.getAuthenticationManager();
        }

}
