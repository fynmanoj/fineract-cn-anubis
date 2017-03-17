/*
 * Copyright 2017 The Mifos Initiative.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.mifos.anubis.provider;

import io.mifos.anubis.api.v1.domain.Signature;
import io.mifos.anubis.config.TenantSignatureProvider;
import io.mifos.core.lang.security.RsaPublicKeyBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.util.Optional;

/**
 * @author Myrle Krantz
 */
@Component
public class TenantRsaKeyProvider {

  private final TenantSignatureProvider tenantSignatureProvider;

  @Autowired
  public TenantRsaKeyProvider(final TenantSignatureProvider tenantSignatureProvider)
  {
    this.tenantSignatureProvider = tenantSignatureProvider;
  }

  public PublicKey getPublicKey(final String tokenVersion) throws InvalidKeyVersionException {
    final Optional<Signature> tenantAuthorizationData =
        tenantSignatureProvider.getSignature(tokenVersion);

    return
        tenantAuthorizationData.map(x -> new RsaPublicKeyBuilder()
        .setPublicKeyMod(x.getPublicKeyMod())
        .setPublicKeyExp(x.getPublicKeyExp())
        .build()).orElseThrow(() -> new InvalidKeyVersionException(tokenVersion + " + not initialized."));
  }
}