package org.apache.shiro.cdi.producers;

import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SessionStorageEvaluator;

import javax.enterprise.inject.New;
import javax.enterprise.inject.Produces;

public class SubjectDaoProducer {

    @Produces
    DefaultSubjectDAO subjectDAO(@New DefaultSubjectDAO subjectDAO, SessionStorageEvaluator sessionStorageEvaluator) {
        subjectDAO.setSessionStorageEvaluator(sessionStorageEvaluator);
        return subjectDAO;
    }
}
