/*
 * Copyright (c) 2015, 2020 Oracle and/or its affiliates. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0, which is available at
 * http://www.eclipse.org/legal/epl-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception, which is available at
 * https://www.gnu.org/software/classpath/license.html.
 *
 * SPDX-License-Identifier: EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0
 */
// Portions Copyright (c) 2022 Pyara Foundation and/or its affiliates

package org.glassfish.soteria.mechanisms.jaspic;

import static jakarta.security.enterprise.AuthenticationStatus.NOT_DONE;
import static jakarta.security.enterprise.AuthenticationStatus.SEND_FAILURE;
import static org.glassfish.soteria.mechanisms.jaspic.Jaspic.fromAuthenticationStatus;
import static org.glassfish.soteria.mechanisms.jaspic.Jaspic.setLastAuthenticationStatus;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import jakarta.security.auth.message.AuthException;
import jakarta.security.auth.message.AuthStatus;
import jakarta.security.auth.message.MessageInfo;
import jakarta.security.auth.message.MessagePolicy;
import jakarta.security.auth.message.config.ServerAuthContext;
import jakarta.security.auth.message.module.ServerAuthModule;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.glassfish.soteria.cdi.CdiUtils;
import org.glassfish.soteria.cdi.spi.CDIPerRequestInitializer;
import org.glassfish.soteria.mechanisms.BasicAuthenticationMechanism;
import org.glassfish.soteria.mechanisms.CustomFormAuthenticationMechanism;
import org.glassfish.soteria.mechanisms.FormAuthenticationMechanism;
import org.glassfish.soteria.mechanisms.HttpMessageContextImpl;

/**
 *
 * @author Arjan Tijms
 * @author Patrik Dudits
 */
public class HttpBridgeServerAuthModule implements ServerAuthModule {

    private final static Map<String, String> mappings = new HashMap<>();

    static {
        mappings.put("Basic", BasicAuthenticationMechanism.class.getName());
        mappings.put("Form", FormAuthenticationMechanism.class.getName());
        mappings.put("CustomForm", CustomFormAuthenticationMechanism.class.getName());
        mappings.put("JWT", "fish.payara.microprofile.jwtauth.eesecurity.JWTAuthenticationMechanism");
        mappings.put("Certificate", "fish.payara.security.realm.mechanisms.CertificateAuthenticationMechanism");
        mappings.put("OAuth2", "fish.payara.security.oauth2.OAuth2AuthenticationMechanism");
        mappings.put("OIDC", "fish.payara.security.openid.OpenIdAuthenticationMechanism");
        mappings.put("JakartaOIDC", "org.glassfish.soteria.mechanisms.OpenIdAuthenticationMechanism");
        mappings.put("TwoIdentityStore", "fish.payara.security.authentication.twoIdentityStore.TwoIdentityStoreAuthenticationMechanism");
    }

    private final Class<?>[] supportedMessageTypes = new Class[]{HttpServletRequest.class, HttpServletResponse.class};

    private final CDIPerRequestInitializer cdiPerRequestInitializer;

    private final Map<String, Class<? extends HttpAuthenticationMechanism>> mechanismClassCache = new ConcurrentHashMap<>(3);

    private CallbackHandler handler;

    public HttpBridgeServerAuthModule(CDIPerRequestInitializer cdiPerRequestInitializer) {
        this.cdiPerRequestInitializer = cdiPerRequestInitializer;
    }

    @Override
    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, @SuppressWarnings("rawtypes") Map options) throws AuthException {
        this.handler = handler;
        // options not supported.
    }

        /**
         * A Servlet Container Profile compliant implementation should return HttpServletRequest and HttpServletResponse, so
         * the delegation class {@link ServerAuthContext} can choose the right SAM to delegate to.
         */
        @Override
        public Class<?>[] getSupportedMessageTypes() {
            return supportedMessageTypes;
        }

        @Override
        public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
            
            HttpMessageContext msgContext = new HttpMessageContextImpl(handler, messageInfo, clientSubject);
            
            if (cdiPerRequestInitializer != null) {
                cdiPerRequestInitializer.init(msgContext.getRequest());
            }
            
            AuthenticationStatus status = NOT_DONE;
            setLastAuthenticationStatus(msgContext.getRequest(), status);
                
            try {
                HttpAuthenticationMechanism mechanismInstance = getMechanism(msgContext);
                status = mechanismInstance
                            .validateRequest(
                                msgContext.getRequest(), 
                                msgContext.getResponse(), 
                                msgContext);
            } catch (AuthenticationException e) {
                // In case of an explicit AuthException, status will
                // be set to SEND_FAILURE, for any other (non checked) exception
                // the status will be the default NOT_DONE
                setLastAuthenticationStatus(msgContext.getRequest(), SEND_FAILURE);
                throw (AuthException) new AuthException("Authentication failure in HttpAuthenticationMechanism").initCause(e);
            }
            
            setLastAuthenticationStatus(msgContext.getRequest(), status);
            
            return fromAuthenticationStatus(status);
        }

    private HttpAuthenticationMechanism getMechanism(HttpMessageContext ctx) throws AuthException {
        String mechanism = getMechanismName(ctx.getRequest());
        Class<? extends HttpAuthenticationMechanism> mechanismClass = findMechanismClass(mechanism);
        return CdiUtils.getBeanReference(mechanismClass);
    }

    private String getMechanismName(HttpServletRequest request) {
        return request.getServletContext().getInitParameter("fish.payara.security.mechanism");
    }

    /**
     * Define the HttpAuthenticationMechanism to use. based on the 'fish.payara.security.mechanism' context parameter if specified.
     *
     * @param mechanism
     * @return
     * @throws ClassNotFoundException
     */
    private Class<? extends HttpAuthenticationMechanism> findMechanismClass(String mechanism) throws AuthException {
        if (mechanism == null) {
            return HttpAuthenticationMechanism.class;
        }
        String mappedName = mappings.getOrDefault(mechanism, mechanism);
        try {
            return mechanismClassCache.computeIfAbsent(mappedName, this::loadMechanismClass);
        } catch (RuntimeException e) {
            throw new AuthException(e.getMessage());
        }

    }

    private Class<? extends HttpAuthenticationMechanism> loadMechanismClass(String mechanism) {
        try {
            Class<?> mechanismClass = Thread.currentThread().getContextClassLoader().loadClass(mechanism);
            if (HttpAuthenticationMechanism.class.isAssignableFrom(mechanismClass)) {
                return (Class<? extends HttpAuthenticationMechanism>) mechanismClass;
            } else {
                throw new IllegalArgumentException("Provided authentication class does not implement HttpAuthentication Mechanism: " + mechanism);
            }
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("HTTP Authentication mechanism class not found " + e.getMessage());
        }
    }

    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        HttpMessageContext msgContext = new HttpMessageContextImpl(handler, messageInfo, null);

        try {
            HttpAuthenticationMechanism mechanismInstance = getMechanism(msgContext);
            AuthenticationStatus status = mechanismInstance
                    .secureResponse(
                            msgContext.getRequest(),
                            msgContext.getResponse(),
                            msgContext);
            AuthStatus authStatus = fromAuthenticationStatus(status);
            if (authStatus == AuthStatus.SUCCESS) {
                return AuthStatus.SEND_SUCCESS;
            }
            return authStatus;
        } catch (AuthenticationException e) {
            throw (AuthException) new AuthException("Secure response failure in HttpAuthenticationMechanism").initCause(e);
        } finally {
            if (cdiPerRequestInitializer != null) {
                cdiPerRequestInitializer.destroy(msgContext.getRequest());
            }
        }

    }

    /**
     * Called in response to a {@link HttpServletRequest#logout()} call.
     */
    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        HttpMessageContext msgContext = new HttpMessageContextImpl(handler, messageInfo, subject);

        getMechanism(msgContext).cleanSubject(msgContext.getRequest(), msgContext.getResponse(), msgContext);
    }

}
