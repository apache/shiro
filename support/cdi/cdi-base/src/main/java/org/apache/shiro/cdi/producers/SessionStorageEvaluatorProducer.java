package org.apache.shiro.cdi.producers;

import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;

import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

public class SessionStorageEvaluatorProducer {

    @Produces
    DefaultSessionStorageEvaluator sessionStorageEvaluator(@New DefaultSessionStorageEvaluator sessionStorageEvaluator) {
        return sessionStorageEvaluator;
    }
}
