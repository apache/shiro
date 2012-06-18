package org.apache.shiro.event;

import org.apache.shiro.subject.Subject;

/**
 * @since 1.3
 */
public class SubjectEvent extends ShiroEvent {

    private final Subject subject;

    public SubjectEvent(Subject subject) {
        super(subject);
        this.subject = subject;
    }

    public Subject getSubject() {
        return subject;
    }
}
