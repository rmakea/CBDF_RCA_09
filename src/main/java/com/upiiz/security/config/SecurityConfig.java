package com.upiiz.security.config;

import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.swing.text.PasswordView;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    // SECUITY FILTER CHAIN - Cadena de filtros de seguridad
    //Bean - Single
    @Autowired
    AuthenticationConfiguration authenticationConfiguration;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        // Definir los filtros generalizados
        return httpSecurity
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(sesion->sesion.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http->{
                    http.requestMatchers(HttpMethod.GET, "/api/v2/listar").hasAuthority("READ");
                    http.requestMatchers(HttpMethod.PUT, "/api/v2/actualizar").hasAuthority("UPDATE");
                    http.requestMatchers(HttpMethod.DELETE, "/api/v2/eliminar").hasAuthority("DELETE");
                    http.requestMatchers(HttpMethod.POST, "/api/v2/crear").hasAuthority("CREATE");
                    http.anyRequest().denyAll();
                })
                .build();
    }

    // Autentiation Manager - Lon vamos a obtener de una instancia que ya existe
    @Bean
    public AuthenticationManager authenticationManager() throws Exception{
        return authenticationConfiguration.getAuthenticationManager();
    }

    // Autentication Provider - DAO -  Va a proporcionar los usuarios
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        return daoAuthenticationProvider;
    }

    // PasswordEncoder
    @Bean
    public PasswordEncoder passwordEncoder(){
        //return new BCryptPasswordEncoder():
        return NoOpPasswordEncoder.getInstance();
    }

    // UserDetailService - Base de Datos o ususarios en Memoria
    @Bean
    public UserDetailsService userDetailsService(){
        // Definir usuarios en memoria
        // No vamos a obtener de una base de datos
        UserDetails usuarioMiguel = User.withUsername("Miguel")
                .password("miguel1234")
                .roles("Admin")
                .authorities("READ", "CREATE", "UPDATE", "DELETE")
                .build();
        UserDetails usuarioRodrigo = User.withUsername("Rodrigo")
                .password("rodri1234")
                .roles("User")
                .authorities("READ", "UPDATE")
                .build();
        UserDetails usuarioInvitado = User.withUsername("guest")
                .password("guest1234")
                .roles("GUEST")
                .authorities("READ")
                .build();
        List<UserDetails> userDetailsList = new ArrayList<>();
        userDetailsList.add(usuarioMiguel);
        userDetailsList.add(usuarioRodrigo);
        userDetailsList.add(usuarioInvitado);

        return new InMemoryUserDetailsManager(userDetailsList);
    }

}
