package org.apache.shiro.cdi.producers;

import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;

import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

public class AuthenticationStrategyProducer {

    @Produces
    protected AtLeastOneSuccessfulStrategy authenticationStrategy(@New AtLeastOneSuccessfulStrategy authenticationStrategy) {
        return authenticationStrategy;
    }

}
