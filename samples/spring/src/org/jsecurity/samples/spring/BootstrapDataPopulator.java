package org.jsecurity.samples.spring;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 */
public class BootstrapDataPopulator implements InitializingBean {

    private static final String CREATE_TABLES = "create table users (\n" +
        "    username varchar(255) primary key,\n" +
        "    password varchar(255) not null\n" +
        ");\n" +
        "\n" +
        "create table roles (\n" +
        "    role_name varchar(255) primary key\n" +
        ");\n" +
        "\n" +
        "create table user_roles (\n" +
        "    username varchar(255) not null,\n" +
        "    role_name varchar(255) not null,\n" +
        "    constraint user_roles_uq unique ( username, role_name )\n" +
        ");\n" +
        "\n" +
        "create table roles_permissions (\n" +
        "    role_name varchar(255) not null,\n" +
        "    permission_class varchar(255) not null,\n" +
        "    permission_target varchar(255) not null,\n" +
        "    permission_actions varchar(255),\n" +
        "    primary key (role_name, permission_class, permission_target, permission_actions)\n" +
        ");";

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected DataSource dataSource = null;

    public void setDataSource( DataSource dataSource ) {
        this.dataSource = dataSource;
    }

    public void afterPropertiesSet() throws Exception {
        //because we're using an in-memory hsqldb for the sample app, a new one will be created each time the
        //app starts, so create the tables and insert the 2 sample users on bootstrap:
        
        JdbcTemplate jdbcTemplate = new JdbcTemplate( this.dataSource );
        jdbcTemplate.execute( CREATE_TABLES );

        //password is 'user1' hashed:
        String query = "insert into users values ('user1', 's9qne0wEqVUbh4HQMZH+CY8yXmc=')";
        jdbcTemplate.execute( query );
        log.debug( "Created user1." );

        //password is 'user2' hashed:
        query = "insert into users values ( 'user2', 'oYgcBu7JbbmQHHu/5BxCo/COnLQ=' )";
        jdbcTemplate.execute( query );
        log.debug( "Created user2." );

        query = "insert into roles values ( 'role1' )";
        jdbcTemplate.execute( query );
        log.debug( "Created role1" );

        query = "insert into roles values ( 'role2' )";
        jdbcTemplate.execute( query );
        log.debug( "Created role2" );

        query = "insert into user_roles values ( 'user1', 'role1' )";
        jdbcTemplate.execute( query );
        query = "insert into user_roles values ( 'user1', 'role2' )";
        jdbcTemplate.execute( query );
        log.debug( "Assigned user1 roles role1 and role2" );

        query = "insert into user_roles values ( 'user2', 'role2' )";
        jdbcTemplate.execute( query );
        log.debug( "Assigned user2 role role2" );
    }
}
