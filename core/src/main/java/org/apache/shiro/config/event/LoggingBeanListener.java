package org.apache.shiro.config.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A stock bean listener implementation that logs all events via the standard logging mechanism.
 */
public class LoggingBeanListener extends BeanListenerSupport {

    private static final Logger logger = LoggerFactory.getLogger(LoggingBeanListener.class);

    @Override
    protected void onUnhandledBeanEvent(BeanEvent beanEvent) {
        logger.warn("UNHANDLED EVENT :: {} :: {}", beanEvent.getBeanName(), beanEvent.getBean());
    }

    @Override
    protected void onInstantiatedBeanEvent(InstantiatedBeanEvent beanEvent) {
        logger.info("INSTANTIATED :: {} :: {}", beanEvent.getBeanName(), beanEvent.getBean());
    }

    @Override
    protected void onConfiguredBeanEvent(ConfiguredBeanEvent beanEvent) {
        logger.info("CONFIGURED :: {} :: {}", beanEvent.getBeanName(), beanEvent.getBean());
    }

    @Override
    protected void onDestroyedBeanEvent(DestroyedBeanEvent beanEvent) {
        logger.info("DESTROYED :: {} :: {}", beanEvent.getBeanName(), beanEvent.getBean());
    }
}
