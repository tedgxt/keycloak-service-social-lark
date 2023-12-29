package org.keycloak.social.lark;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;


public class LarkIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    public LarkIdentityProviderConfig() {
        super();
    }

    public LarkIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }
}
