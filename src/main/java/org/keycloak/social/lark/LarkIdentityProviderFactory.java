package org.keycloak.social.lark;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * {@code @Author:} guanxiatao
 * {@code @Date:} 2021/3/15 5:14 下午
 */

public class LarkIdentityProviderFactory extends AbstractIdentityProviderFactory<LarkIdentityProvider> implements SocialIdentityProviderFactory<LarkIdentityProvider> {

    public static final String PROVIDER_ID = "lark";

    @Override
    public String getName() {
        return "飞书";
    }

    @Override
    public LarkIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new LarkIdentityProvider(session, new LarkIdentityProviderConfig(model));
    }

    @Override
    public LarkIdentityProviderConfig createConfig() {
        return new LarkIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
