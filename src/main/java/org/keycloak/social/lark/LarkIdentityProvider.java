package org.keycloak.social.lark;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Strings;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LarkIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
        implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {
    protected static final Logger logger = Logger.getLogger(LarkIdentityProvider.class);

    public static final String AUTH_URL = "https://open.feishu.cn/open-apis/authen/v1/index";
    public static final String DEFAULT_SCOPE = "snsapi_login";
    public static final String PROFILE_URL = "https://open.feishu.cn/open-apis/authen/v1/user_info?lang=zh_CN";
    public static final String TOKEN_URL = "https://open.feishu.cn/open-apis/authen/v1/access_token";
    public static final String APP_TOKEN_URL = "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal/";

    public static final String OAUTH2_PARAMETER_CLIENT_ID = "app_id";
    public static final String OAUTH2_PARAMETER_CLIENT_SECRET = "app_secret";
    public static final String LARK_OAUTH2_PARAMETER_APP_ACCESS_TOKEN = "app_access_token";

    public static final String USER_ATTRIBUTE_PHONE_NUMBER = "phone_number";

    public static final String RESPONSE_CODE_SUCCESS = "0";

    public LarkIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event);
    }

    protected boolean supportsExternalExchange() {
        return true;
    }

    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        JsonNode userInfo = profile.get("data");
        String unionId = getJsonProperty(userInfo, "union_id");
        BrokeredIdentityContext user = new BrokeredIdentityContext(
                (unionId != null && unionId.length() > 0 ? unionId : getJsonProperty(userInfo, "open_id")));
        String name = getJsonProperty(userInfo, "name");
        String email = getJsonProperty(userInfo, "email");
        user.setUsername(Optional.ofNullable(email).orElse("input your email"));
        user.setBrokerUserId(getJsonProperty(userInfo, "user_id"));
        user.setModelUsername(Optional.ofNullable(email).orElse("input your email"));

        user.setName(name);
        user.setEmail(Optional.ofNullable(email).orElse("input your email"));
        user.setIdpConfig(getConfig());
        user.setIdp(this);
        user.setUserAttribute(USER_ATTRIBUTE_PHONE_NUMBER, getJsonProperty(userInfo, "mobile"));

        user.setLastName(name);
        user.setFirstName(name);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
        return user;
    }

    public BrokeredIdentityContext getFederatedIdentity(String response) {
        String accessToken = extractTokenFromResponse(response, getAccessTokenResponseParameter());

        try {
            JsonNode profile = mapper.readTree(response);
            String respCode = getJsonProperty(profile, "code");
            if (RESPONSE_CODE_SUCCESS.equals(respCode)) {
                BrokeredIdentityContext user = extractIdentityFromProfile(null, profile);
                user.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);

                return user;
            } else {
                throw new IdentityBrokerException("get user info failed, error：" + JsonSerialization.writeValueAsString(profile));
            }

        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from lark.", e);
        }
    }

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try {
            JsonNode profile = SimpleHttp.doGet(getConfig().getUserInfoUrl(), session).auth(accessToken).asJson();
            String respCode = getJsonProperty(profile, "code");
            if (RESPONSE_CODE_SUCCESS.equals(respCode)) {
                return extractIdentityFromProfile(null, profile);
            } else {
                throw new IdentityBrokerException("get user info failed, error：" + JsonSerialization.writeValueAsString(profile));
            }

        } catch (Exception e) {
            throw new IdentityBrokerException("Could not obtain user profile from github.", e);
        }
    }

    protected String extractTokenFromResponse(String response, String tokenName) {
        if (response == null)
            return null;

        if (response.startsWith("{")) {
            try {
                JsonNode jsonResponse = mapper.readTree(response);
                if (jsonResponse.has("data")) {
                    JsonNode data = jsonResponse.get("data");
                    if (data.has(tokenName)) {
                        String s = data.get(tokenName).textValue();
                        if (s == null || s.trim().isEmpty())
                            return null;
                        return s;
                    }
                } else {
                    return null;
                }
            } catch (IOException e) {
                throw new IdentityBrokerException("Could not extract token [" + tokenName + "] from response [" + response + "] due: " + e.getMessage(), e);
            }
        } else {
            Matcher matcher = Pattern.compile(tokenName + "=([^&]+)").matcher(response);

            if (matcher.find()) {
                return matcher.group(1);
            }
        }

        return null;
    }

    public Response performLogin(AuthenticationRequest request) {
        try {
            URI authorizationUrl = createAuthorizationUrl(request).build();
            return Response.seeOther(authorizationUrl).build();
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication request.", e);
        }
    }

    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        final UriBuilder uriBuilder;
        uriBuilder = UriBuilder.fromUri(getConfig().getAuthorizationUrl());
        uriBuilder.queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
                .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
                .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri());
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


    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    protected class Endpoint {
        protected AuthenticationCallback callback;
        protected RealmModel realm;
        protected EventBuilder event;

        @Context
        protected KeycloakSession session;

        @Context
        protected ClientConnection clientConnection;

        @Context
        protected HttpHeaders headers;

        @Context
        protected UriInfo uriInfo;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
            this.callback = callback;
            this.realm = realm;
            this.event = event;
        }

        public String generateAppTokenRequest() throws Exception {
            Map<String, String> appTokenReqBody = new HashMap<>();

            appTokenReqBody.put(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId());
            // Workaround for clientSecret, because secret from getConfig().getClientSecret() is encrypted.
            // Lark ask developer put client secret into request body when invoking API to get app token.
            String clientSecret = getConfig().getConfig().get("clientsecret");
            appTokenReqBody.put(OAUTH2_PARAMETER_CLIENT_SECRET, clientSecret);

            String appTokenResp = SimpleHttp.doPost(APP_TOKEN_URL, session).json(appTokenReqBody).asString();
            if (appTokenResp == null) {
                logger.warn("get app token response is null");
                return null;
            }

            // logger.info("get app token response: " + appTokenResp);

            if (appTokenResp.startsWith("{")) {
                try {
                    JsonNode node = mapper.readTree(appTokenResp);
                    if (node.has(LARK_OAUTH2_PARAMETER_APP_ACCESS_TOKEN)) {
                        String s = node.get(LARK_OAUTH2_PARAMETER_APP_ACCESS_TOKEN).textValue();
                        if (s == null || s.trim().isEmpty())
                            return null;
                        return s;
                    } else {
                        return null;
                    }
                } catch (IOException e) {
                    throw new IdentityBrokerException("Could not extract app token [" + LARK_OAUTH2_PARAMETER_APP_ACCESS_TOKEN + "] from response [" + appTokenResp + "] due: " + e.getMessage(), e);
                }
            } else {
                Matcher matcher = Pattern.compile(LARK_OAUTH2_PARAMETER_APP_ACCESS_TOKEN + "=([^&]+)").matcher(appTokenResp);

                if (matcher.find()) {
                    return matcher.group(1);
                }
            }

            return null;
        }

        @GET
        @Produces("application/json;charset=utf-8")
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            logger.info("OAUTH2_PARAMETER_CODE=" + authorizationCode);
            if (error != null) {
                if (error.equals(ACCESS_DENIED)) {
                    logger.error(ACCESS_DENIED + " for broker login " + getConfig().getProviderId());
                    return callback.cancelled(state);
                } else {
                    logger.error(error + " for broker login " + getConfig().getProviderId());
                    return callback.error(state, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }
            }

            // todo: refresh token
            try {
                if (authorizationCode != null) {
                    // get app_access_token by clientId and clientSecret
                    String appToken = generateAppTokenRequest();

                    // get access_token and user info
                    String response = generateTokenRequest(authorizationCode, appToken).asString();

                    BrokeredIdentityContext federatedIdentity = getFederatedIdentity(response);
                    if (getConfig().isStoreToken()) {
                        if (federatedIdentity.getToken() == null)
                            federatedIdentity.setToken(authorizationCode);
                    }

                    federatedIdentity.setIdpConfig(getConfig());
                    federatedIdentity.setIdp(LarkIdentityProvider.this);
                    federatedIdentity.setCode(state);

                    return callback.authenticated(federatedIdentity);
                }
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (Exception e) {
                logger.error("Failed to make identity provider oauth callback", e);
            }
            event.event(EventType.LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY,
                    Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }

        public SimpleHttp generateTokenRequest(String authorizationCode, String appToken) {
            Map<String, String> requestBody = new HashMap<>();

            requestBody.put(OAUTH2_PARAMETER_CODE, authorizationCode);
            requestBody.put(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE);

            return SimpleHttp.doPost(getConfig().getTokenUrl(), session).auth(appToken).json(requestBody);
        }
    }
}