package org.jsecurity.authz;

import java.util.Set;

/**
 * An <tt>TargetedPermission</tt> represents an action or actions that might be performed on a single
 * identifiable resource instance or on multiple resources/instances of a particular type.  That is, the permission's
 * actions are <em>targeted</em> at a particular resource or all resources of a particular type.
 *
 * <p>The {@link #getName() name} of a <tt>TargetedPermission</tt> is a resource's 
 * <tt>identifier</tt>, or the {@link #WILDCARD WILDCARD} constant if the <tt>TargetedPermission</tt> is to represent
 * all resources of a particular type.
 *
 * <p>A resource's identifier is obtained in a system-specific manner.  For example,
 * in most database-driven applications, this identifier is usally a primary key value that is
 * obtained from an entity instance's <tt>getId()</tt> (or similar) method.  For a file-based resource, the identifier
 * could be the fully qualified path of the file.  A network-based resource could be a fully-qualified URL.
 *
 * <p>Most <tt>TargetedPermission</tt> instances will have an &quot;actions&quot; <tt>Set</tt> that specifies the
 * behavior allowed on the resource(s) identified by the target's {@link #getName() name}.  For example a
 * <tt>FilePermission</tt> class might have the total possible actions of &quot;read&quot;, &quot;write&quot;,
 * &quot;execute&quot;, and &quot;delete&quot;.  A specific instance of the <tt>FilePermission</tt> might have a
 * target name of "/bin/bash" with actions of &quot;read&quot; and &quot;execute&quot;, meaning whomever is granted
 * that permission could only read and execute <tt>/bin/bash</tt>, but not write to it or delete it.
 *
 * <p>The {@link #WILDCARD WILDCARD} constant when used in the {@link #getName name} attribute represents <b>all</b>
 * instances and/or resources of a particular type.  When used in the {@link #getActionsSet() actions} attribute, it
 * represents <b>all</b> possible actions.
 *
 * <p>Some examples:
 *
 * <p>This instance:
 *
 * <pre>new com.domain.PrinterPermission( WILDCARD, "print" );</pre>
 *
 * means anyone (user, role, etc) granted that permission instance would have
 * the ability to "print" documents to any printer available to a system.  Such a permission
 * could be assigned to all users in a system where printers are not considered
 * restricted resources - then any user may print to any printer they wish.
 *
 * <p>This instance:
 * <pre>new com.domain.UserPermission( aUser.getId(), "read, write" );</pre>
 *
 * means anyone granted that permission would have
 * the ability to "read" (view) and "write" (change) the user account data for the user with the
 * system id <tt>aUser.getId()</tt>.  Such a permission might be associated with the user
 * account with the same Id so the user could edit their own account information.
 *
 * <p>Finally, this instance:
 * <pre>new com.domain.UserPermission( WILDCARD, WILDCARD );</pre>
 *
 * means anyone granted that permission would have the
 * ability to do anything (create, read, update, delete) to <em>any</em> user account.  Such a
 * permission would generally be assigned to an administrative role.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public interface TargetedPermission extends Permission {

    /**
     * Returns the resource and/or target's name.  That is, if this Permission and its actions are targed at a specific
     * resource, this method returns the name of that resource.  For example, this instance:<br/><br/>
     *
     * <pre>new FilePermission( "/bin/bash", "execute" );</pre>
     *
     * <p>would have a <tt>name</tt> of &quot;/bin/bash&quot;, since that is the <em>name</em> of actions
     * represented by this permission (&quot;execute&quot;).
     *
     * @return the name of the target corresponding to the permission's actions, or <tt>null</tt> if no specific
     * resource is targeted.
     */
    String getName();

    /**
     * Returns all actions represented by the permission instance, or <tt>null</tt> if there are none.
     *
     * <p>If the permission is {@link #getName targeted}, these are the actions associated with that target
     *
     * @return all actions represented by the permission instance or <tt>null</tt> if there are none.
     */
    Set<String> getActionsSet();

    /**
     * Returns the canonically ordered String containing all actions represented by this permission
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
