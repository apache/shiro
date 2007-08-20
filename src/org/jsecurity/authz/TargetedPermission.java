package org.jsecurity.authz;

import java.util.Set;

/**
 * TODO - IN PROGRESS
 *
 *  * <p>Most Permission instances will have an &quot;actions&quot; <tt>Set</tt> that specifies the behavior
 * allowed on the resource identified by the name {@link #getName() name}.  For example a <tt>FilePermission</tt>
 * class might have the total actions possible of &quot;read&quot;, &quot;write&quot;, &quot;execute&quot;, and
 * &quot;delete&quot;.  A specific instance of the <tt>FilePermission</tt> might have a targetName of "/bin/bash" with
 * actions of &quot;read&quot; and &quot;execute&quot;, meaning whomever is granted that permission could only read and
 * execute <tt>/bin/bash</tt>, but not write to it or delete it.
 *
 * TODO class JavaDoc
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public interface TargetedPermission extends Permission {

    /**
     * Returns the name's name.  That is, if this Permission and its actions are targed at a specific
     * resource, this method returns the name of that resource.  For example, this instance:<br/><br/>
     *
     * <pre>new FilePermission( "/bin/bash", "execute" );</pre>
     *
     * <p>would have a <tt>targetName</tt> of &quot;/bin/bash&quot;, since that is the <em>name</em> of actions
     * represented by this permission (&quot;execute&quot;).
     *
     * @return the name of the name corresponding to the permission's actions, or <tt>null</tt> if no specific
     * resource is targeted.
     */
    String getName();

    /**
     * Returns all actions represented by the permission instance, or <tt>null</tt> if there are none.
     *
     * <p>If the permission is {@link #getName targeted}, these are the actions associated with that name
     *
     * @return all actions represented by the permission instance or <tt>null</tt> if there are none.
     */
    Set<String> getActionsSet();

    /**
     * Returns the canonically ordered String containing all actions represented by a permission
     * instance, or <tt>null</tt> if there are no actions.  The string must be composed of, and match exactly, those
     * actions in the {@link #getActions actions} set.
     *
     * <p>For example, a FilePermission class might have the total possible actions of <tt>read</tt>, <tt>write</tt>,
     * <tt>execute</tt> and <tt>delete</tt>.  If there were a FilePermission for a name of
     * <tt>/home/jsmith</tt>, a FilePermission instance for that file might return an actions string of
     * &quot;read,write&quot; only.
     *
     * @return the canonically ordered string representation of this instance's permission actions, or <tt>null</tt> if
     * there are none.
     */
    String getActions();

}
