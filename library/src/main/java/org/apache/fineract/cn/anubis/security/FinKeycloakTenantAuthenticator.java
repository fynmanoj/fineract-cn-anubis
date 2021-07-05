package org.apache.fineract.cn.anubis.security;

import com.google.gson.Gson;
import io.jsonwebtoken.*;
import org.apache.fineract.cn.anubis.annotation.AcceptedTokenType;
import org.apache.fineract.cn.anubis.api.v1.TokenConstants;
import org.apache.fineract.cn.anubis.api.v1.domain.TokenContent;
import org.apache.fineract.cn.anubis.api.v1.domain.TokenPermission;
import org.apache.fineract.cn.anubis.provider.InvalidKeyTimestampException;
import org.apache.fineract.cn.anubis.provider.TenantRsaKeyProvider;
import org.apache.fineract.cn.anubis.service.PermittableService;
import org.apache.fineract.cn.anubis.token.TokenType;
import org.apache.fineract.cn.lang.ApplicationName;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.apache.fineract.cn.anubis.config.AnubisConstants.LOGGER_NAME;

/**
 * @author manoj
 */
@Component
public class FinKeycloakTenantAuthenticator {
 private final TenantRsaKeyProvider tenantRsaKeyProvider;
 private final String applicationNameWithVersion;
 private final Gson gson;
 private final Set<ApplicationPermission> guestPermissions;
 private final Logger logger;

 @Autowired
 public FinKeycloakTenantAuthenticator(
         final TenantRsaKeyProvider tenantRsaKeyProvider,
         final ApplicationName applicationName,
         final PermittableService permittableService,
         final @Qualifier("anubisGson") Gson gson,
         final @Qualifier(LOGGER_NAME) Logger logger) {
  this.tenantRsaKeyProvider = tenantRsaKeyProvider;
  this.applicationNameWithVersion = applicationName.toString();
  this.gson = gson;
  this.guestPermissions
          = permittableService.getPermittableEndpointsAsPermissions(AcceptedTokenType.GUEST);
  this.logger = logger;
 }

 AnubisAuthentication authenticate(
         final @Nonnull String user,
         final @Nonnull String token,
         final @Nonnull String keyTimestamp) {
  try {
/*   final JwtParser parser = Jwts.parser()
           .requireSubject(user)
           .requireIssuer(TokenType.TENANT.getIssuer())
           .setSigningKey(tenantRsaKeyProvider.getPublicKey(keyTimestamp));

   @SuppressWarnings("unchecked") Jwt<Header, Claims> jwt = parser.parse(token);*/

   //final String serializedTokenContent = jwt.getBody().get(TokenConstants.JWT_CONTENT_CLAIM, String.class);
   final String serializedTokenContent = "{\"tokenPermissions\":[{\"path\":\"identity-v1/permittablegroups/*\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]},{\"path\":\"customer-v1/customers/*/tasks/*\",\"allowedOperations\":[\"CHANGE\"]},{\"path\":\"identity-v1/applications/*/permissions/*/users/{useridentifier}/enabled\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]},{\"path\":\"deposit-v1/collection\",\"allowedOperations\":[\"CHANGE\"]},{\"path\":\"accounting-v1/trialbalance\",\"allowedOperations\":[\"READ\"]},{\"path\":\"accounting-v1/accounts/*/entries\",\"allowedOperations\":[\"READ\"]},{\"path\":\"deposit-v1/instances/transactiontypes\",\"allowedOperations\":[\"READ\"]},{\"path\":\"deposit-v1/definitions/*/commands\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"deposit-v1/collection/*\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"customer-v1/catalogs/*/fields/*\",\"allowedOperations\":[\"DELETE\",\"CHANGE\"]},{\"path\":\"accounting-v1/ledgers/*\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]},{\"path\":\"deposit-v1/subtxntype\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"customer-v1/customers/*/identifications\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"accounting-v1/ledgers\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"deposit-v1/instances/*/statement\",\"allowedOperations\":[\"READ\"]},{\"path\":\"deposit-v1/actions\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"deposit-v1/definitions/*\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]},{\"path\":\"customer-v1/nonperson\",\"allowedOperations\":[\"CHANGE\"]},{\"path\":\"customer-v1/customers/*/identifications/*/scans/*/image\",\"allowedOperations\":[\"READ\"]},{\"path\":\"customer-v1/customers/*/identifications/*\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]},{\"path\":\"deposit-v1/instances/*\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"customer-v1/customers/*/documents/*/completed\",\"allowedOperations\":[\"CHANGE\"]},{\"path\":\"accounting-v1/incomestatement\",\"allowedOperations\":[\"READ\"]},{\"path\":\"customer-v1/catalogs/*\",\"allowedOperations\":[\"READ\",\"DELETE\"]},{\"path\":\"accounting-v1/financialcondition\",\"allowedOperations\":[\"READ\"]},{\"path\":\"customer-v1/customers/*/contact\",\"allowedOperations\":[\"CHANGE\"]},{\"path\":\"accounting-v1/ledgers/*/accounts\",\"allowedOperations\":[\"READ\"]},{\"path\":\"accounting-v1/transactiontypes/*\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"customer-v1/catalogs\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"deposit-v1/definitions/*/instances\",\"allowedOperations\":[\"READ\"]},{\"path\":\"accounting-v1/journal/*\",\"allowedOperations\":[\"READ\"]},{\"path\":\"customer-v1/customers/*/commands\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"accounting-v1/journal\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"customer-v1/person\",\"allowedOperations\":[\"CHANGE\"]},{\"path\":\"customer-v1/customers/*/documents\",\"allowedOperations\":[\"READ\"]},{\"path\":\"accounting-v1/accounts\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"deposit-v1/instances\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"accounting-v1/chartofaccounts\",\"allowedOperations\":[\"READ\"]},{\"path\":\"customer-v1/customers/*/identifications/*/scans\",\"allowedOperations\":[\"READ\"]},{\"path\":\"deposit-v1/definitions/*/dividends\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"accounting-v1/accounts/*/actions\",\"allowedOperations\":[\"READ\"]},{\"path\":\"customer-v1/customers/*/tasks\",\"allowedOperations\":[\"READ\"]},{\"path\":\"identity-v1/users/{useridentifier}/permissions\",\"allowedOperations\":[\"READ\"]},{\"path\":\"accounting-v1/accounts/*\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]},{\"path\":\"deposit-v1/instances/*/balance\",\"allowedOperations\":[\"READ\"]},{\"path\":\"identity-v1/users/*\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]},{\"path\":\"customer-v1/customers/*/actions\",\"allowedOperations\":[\"READ\"]},{\"path\":\"customer-v1/customers/*/identifications/*/scans/*\",\"allowedOperations\":[\"READ\",\"DELETE\"]},{\"path\":\"deposit-v1/transaction\",\"allowedOperations\":[\"CHANGE\"]},{\"path\":\"customer-v1/customers/*/documents/*/pages\",\"allowedOperations\":[\"READ\"]},{\"path\":\"identity-v1/token/_current\",\"allowedOperations\":[\"DELETE\"]},{\"path\":\"customer-v1/customers\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"customer-v1/customers/*/address\",\"allowedOperations\":[\"CHANGE\"]},{\"path\":\"accounting-v1/transactiontypes\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"deposit-v1/definitions\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"customer-v1/customers/*/portrait\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]},{\"path\":\"customer-v1/customers/*/documents/*/pages/*\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]},{\"path\":\"customer-v1/customers/*\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"customer-v1/tasks/*\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"accounting-v1/accounts/*/commands\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"customer-v1/tasks\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"deposit-v1/subtxntype/*\",\"allowedOperations\":[\"READ\",\"CHANGE\"]},{\"path\":\"identity-v1/users/{useridentifier}/password\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]},{\"path\":\"customer-v1/customers/*/documents/*\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]},{\"path\":\"identity-v1/roles/*\",\"allowedOperations\":[\"READ\",\"DELETE\",\"CHANGE\"]}]}";
   final String sourceApplication = "Keycloak";//jwt.getBody().get(TokenConstants.JWT_SOURCE_APPLICATION_CLAIM, String.class);
   final TokenContent tokenContent = gson.fromJson(serializedTokenContent, TokenContent.class);
   if (tokenContent == null)
    throw AmitAuthenticationException.missingTokenContent();

   final Set<ApplicationPermission> permissions = translatePermissions(tokenContent.getTokenPermissions());
   permissions.addAll(guestPermissions);

   logger.info("Tenant token for user {}, with key timestamp {} authenticated successfully.", user, keyTimestamp);

   return new AnubisAuthentication(TokenConstants.PREFIX + token,
           "operator", applicationNameWithVersion, sourceApplication, permissions
   );
  }
  catch (final JwtException e) {
   logger.info("Tenant token for user {}, with key timestamp {} failed to authenticate. Exception was {}", user, keyTimestamp, e);
   throw AmitAuthenticationException.invalidToken();
  }
 }

 private Set<ApplicationPermission> translatePermissions(
         @Nonnull final List<TokenPermission> tokenPermissions)
 {
  return tokenPermissions.stream()
          .filter(x -> x.getPath().startsWith(applicationNameWithVersion))
          .flatMap(this::getAppPermissionFromTokenPermission)
          .collect(Collectors.toSet());
 }

 private Stream<ApplicationPermission> getAppPermissionFromTokenPermission(final TokenPermission tokenPermission) {
  final String servletPath = tokenPermission.getPath().substring(applicationNameWithVersion.length());
  return tokenPermission.getAllowedOperations().stream().map(x -> new ApplicationPermission(servletPath, x, false));
 }
}
