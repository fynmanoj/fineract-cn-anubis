package org.apache.fineract.cn.anubis.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.fineract.cn.anubis.filter.IsisAuthenticatedProcessingFilter;
import org.apache.fineract.cn.anubis.security.ApplicationPermission;
import org.apache.fineract.cn.anubis.security.FinKeycloakAuthenticationProvider;
import org.apache.fineract.cn.anubis.security.IsisAuthenticatedAuthenticationProvider;
import org.apache.fineract.cn.anubis.security.UrlPermissionChecker;
import org.apache.fineract.cn.lang.ApplicationName;
import org.apache.http.HttpStatus;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.account.KeycloakRole;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.UrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * @author manoj
 */
@Configuration
@EnableWebSecurity
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
@ConditionalOnProperty({"authentication.service.keycloak"})
public class FinKeycloakSecurityConfigurerAdapter extends KeycloakWebSecurityConfigurerAdapter {
 final private Logger logger;
 final private ApplicationName applicationName;

 public FinKeycloakSecurityConfigurerAdapter(final @Qualifier(AnubisConstants.LOGGER_NAME) Logger logger,
                                             final ApplicationName applicationName) {
  this.logger = logger;
  this.applicationName = applicationName;
 }

 static class CustomKeycloakAccessToken extends AccessToken {
  @JsonProperty("roles")
  protected Set<String> roles;

  public Set<String> getRoles() {
   return roles;
  }

  public void setRoles(Set<String> roles) {
   this.roles = roles;
  }
 }

 @Override
 protected KeycloakAuthenticationProvider keycloakAuthenticationProvider() {
  return new KeycloakAuthenticationProvider() {

   @Override
   public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) authentication;
    List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

    for (String role : ((CustomKeycloakAccessToken)((KeycloakPrincipal<KeycloakSecurityContext>)token.getPrincipal()).getKeycloakSecurityContext().getToken()).getRoles()) {
     grantedAuthorities.add(new KeycloakRole(role));
    }

    return new KeycloakAuthenticationToken(token.getAccount(), token.isInteractive(), new SimpleAuthorityMapper().mapAuthorities(grantedAuthorities));
   }

  };
 }

 /*@Autowired
 public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
  auth.authenticationProvider(keycloakAuthenticationProvider());
 }*/

 @Autowired
 public void configureGlobal(
         final AuthenticationManagerBuilder auth,
         @SuppressWarnings("SpringJavaAutowiringInspection") final FinKeycloakAuthenticationProvider provider)
         throws Exception {
  auth.authenticationProvider(provider);
 }

 @Bean
 @Override
 protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
  return new NullAuthenticatedSessionStrategy();
 }
 @Bean
 public KeycloakSpringBootConfigResolver KeycloakConfigResolver() {
  return new KeycloakSpringBootConfigResolver();
 }

 @Bean
 public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
         KeycloakAuthenticationProcessingFilter filter) {
  FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
  registrationBean.setEnabled(false);
  return registrationBean;
 }

 @Bean
 public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(KeycloakPreAuthActionsFilter filter) {
  FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
  registrationBean.setEnabled(false);
  return registrationBean;
 }

 private AccessDecisionManager defaultAccessDecisionManager() {
  final List<AccessDecisionVoter<?>> voters = new ArrayList<>();
  voters.add(new UrlPermissionChecker(logger, applicationName));return new UnanimousBased(voters);
 }

 protected void configure(HttpSecurity http) throws Exception {
  Filter filter = new IsisAuthenticatedProcessingFilter(super.authenticationManager());
  ((HttpSecurity)((HttpSecurity)((HttpSecurity)((HttpSecurity)((UrlAuthorizationConfigurer.StandardInterceptUrlRegistry)((UrlAuthorizationConfigurer.AuthorizedUrl)((UrlAuthorizationConfigurer)((HttpSecurity)((HttpSecurity)http.httpBasic().disable()).csrf().disable()).apply(new UrlAuthorizationConfigurer(this.getApplicationContext()))).getRegistry().anyRequest()).hasAuthority("maats_feather").accessDecisionManager(this.defaultAccessDecisionManager())).and()).formLogin().disable()).logout().disable()).addFilter(filter).sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()).exceptionHandling().accessDeniedHandler((request, response, accessDeniedException) -> {
   response.setStatus(404);
  });
 }

}