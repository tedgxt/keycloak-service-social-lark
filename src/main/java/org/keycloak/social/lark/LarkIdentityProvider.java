package org.keycloak.social.lark;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class LarkIdentityProvider extends AbstractOAuth2IdentityProvider<LarkIdentityProviderConfig> implements SocialIdentityProvider<LarkIdentityProviderConfig> {
    public static final String APP_TOKEN_URL = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/";
    public static final String OAUTH2_PARAMETER_CLIENT_ID = "app_id";
    public static final String OAUTH2_PARAMETER_CLIENT_SECRET = "app_secret";
    public static final String USER_ATTRIBUTE_PHONE_NUMBER = "phone_number";
    public static final String RESPONSE_CODE_SUCCESS = "0";
    protected static final Logger logger = Logger.getLogger(LarkIdentityProvider.class);

    public LarkIdentityProvider(KeycloakSession session, LarkIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl("https://open.feishu.cn/open-apis/authen/v1/authorize");
        config.setTokenUrl("https://open.feishu.cn/open-apis/authen/v1/oidc/access_token");
        config.setUserInfoUrl("https://open.feishu.cn/open-apis/authen/v1/user_info");
    }

    @Override
    protected String getDefaultScopes() {
        return "contact:user.email:readonly contact:user.employee:readonly contact:user.email:readonly contact:user.employee_id:readonly contact:user.phone:readonly";
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        final UriBuilder uriBuilder;
        uriBuilder = UriBuilder.fromUri(getConfig().getAuthorizationUrl());
        uriBuilder.queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId()).queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded()).queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
        String loginHint = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
        if (getConfig().isLoginHint() && loginHint != null) {
            uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
        }

        String prompt = getConfig().getPrompt();
        if (prompt == null || prompt.isEmpty()) {
            prompt = request.getAuthenticationSession().getClientNote(OAuth2Constants.PROMPT);
        }
        if (prompt != null) {
            uriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
        }

        String nonce = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.NONCE_PARAM);
        if (nonce == null || nonce.isEmpty()) {
            nonce = UUID.randomUUID().toString();
            request.getAuthenticationSession().setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
        }
        uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

        String acr = request.getAuthenticationSession().getClientNote(OAuth2Constants.ACR_VALUES);
        if (acr != null) {
            uriBuilder.queryParam(OAuth2Constants.ACR_VALUES, acr);
        }
        return uriBuilder;
    }

    @Override
    public SimpleHttp authenticateTokenRequest(SimpleHttp tokenRequest) {
        Map<String, String> appTokenReqBody = new HashMap<>();
        appTokenReqBody.put(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId());
        String clientSecret = getConfig().getClientSecret();
        appTokenReqBody.put(OAUTH2_PARAMETER_CLIENT_SECRET, clientSecret);
        try {
            JsonNode node = SimpleHttp.doPost(APP_TOKEN_URL, session).json(appTokenReqBody).asJson();
            return tokenRequest.auth(node.get("app_access_token").textValue());
        } catch (IOException e) {
            logger.error("get app token fail", e);
            return tokenRequest;
        }
    }

    @Override
    protected String extractTokenFromResponse(String response, String tokenName) {
        try {
            JsonNode node = mapper.readTree(response);
            return node.get("data").get(tokenName).textValue();
        } catch (JsonProcessingException e) {
            throw new IdentityBrokerException("parse response fail", e);
        }
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        JsonNode profile;
        try {
            profile = SimpleHttp.doGet(getConfig().getUserInfoUrl(), session).auth(accessToken).asJson();
        } catch (IOException e) {
            throw new IdentityBrokerException("get user info failed, error", e);
        }
        String respCode = getJsonProperty(profile, "code");
        if (RESPONSE_CODE_SUCCESS.equals(respCode)) {
            return extractIdentityFromProfile(null, profile);
        } else {
            throw new IdentityBrokerException("get user info failed, error：" + profile.toPrettyString());
        }
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        JsonNode userInfo = profile.get("data");
        String unionId = getJsonProperty(userInfo, "union_id");
        BrokeredIdentityContext user = new BrokeredIdentityContext((unionId != null && !unionId.isEmpty() ? unionId : getJsonProperty(userInfo, "open_id")));
        String name = getJsonProperty(userInfo, "name");
        String email = getJsonProperty(userInfo, "enterprise_email");
        if (email == null || email.isEmpty()) {
            email = getJsonProperty(userInfo, "email");
        }
        user.setUsername(email);
        user.setBrokerUserId(getJsonProperty(userInfo, "user_id"));
        user.setModelUsername(email);
        user.setEmail(email);
        user.setUserAttribute(USER_ATTRIBUTE_PHONE_NUMBER, getJsonProperty(userInfo, "mobile"));
        if (name.length() > 1) {
            String[] parts = name.split("\\s+", 2);
            if (parts.length > 1) {
                user.setFirstName(parts[1]);
                user.setLastName(parts[0]);
            } else {
                user.setFirstName(name.substring(1));
                user.setLastName(name.substring(0, 1));
            }
        } else {
            user.setFirstName(name);
        }
        user.setIdpConfig(getConfig());
        user.setIdp(this);
        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        return user;
    }
}