/*
 * Copyright (C) 2005-2007 All rights reserved.
 */

package org.jsecurity.session.support;

/**
 * Description of class.
 *
 * todo Needs JavaDoc
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public interface SessionValidationScheduler {

    void startSessionValidation();

    void stopSessionValidation();

}