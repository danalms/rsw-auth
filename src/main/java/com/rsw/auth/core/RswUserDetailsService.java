package com.rsw.auth.core;

import com.rsw.auth.domain.*;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;


/**
 * Custom implementation of the JDBC-based Spring Security UserDetailsService
 * This class is explicitly configured as a bean in the SecurityConfig and therefore is not @Service annotated
 *
 */
@Transactional
public class RswUserDetailsService extends JdbcDaoImpl {

    private static final Logger LOGGER = LoggerFactory.getLogger(RswUserDetailsService.class);

    private PasswordService passwordService;

    private static final String DEF_SELECT_USERS_BASE =
            "select u.username, u.password, u.first_name, u.middle_initial, u.last_name, u.email_address, " +
                " u.mobile_number, u.enabled, u.locked, u.password_expiry " +
                " from users u ";
    private static final String DEF_SEARCH_USERS_QUERY = DEF_SELECT_USERS_BASE +
                " where u.last_name LIKE ? " +
                " order by u.last_name";
    static final String DEF_USERS_BY_USERNAME_QUERY = DEF_SELECT_USERS_BASE +
                " where u.username = ?";
    private static final String DEF_USER_EXISTS_SQL =
            "select username from users where username = ?";

    private static final String DEF_USER_AUTHORITIES_BY_USERNAME_QUERY =
            "select distinct a.authority " +
                    " from authorities a " +
                    " where a.username = ? ";
    private static final String DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY =
            "select distinct ga.authority " +
                    " from groups g " +
                    " join group_members gm on g.id = gm.group_id " +
                    " join group_authorities ga on g.id = ga.group_id " +
                    " where gm.username = ? ";
    static final String DEF_GROUPNAMES_BY_USERNAME_QUERY =
            "select distinct g.group_name " +
                    " from groups g " +
                    " join group_members gm on g.id = gm.group_id " +
                    " where gm.username = ? ";

    private static final String DEF_CREATE_USER_SQL =
            "insert into users " +
                "(username, password, enabled, locked, password_expiry, " +
                " first_name, middle_initial, last_name, email_address, mobile_number) " +
                "values (?,?,?,?,?,?,?,?,?,?)";

    private static final String DEF_UPDATE_PROFILE_BASE =
            "update users set " +
                " first_name = ? , " +
                " middle_initial = ? ," +
                " last_name = ? ," +
                " email_address = ? ," +
                " mobile_number = ? ";
    private static final String DEF_UPDATE_PROFILE = DEF_UPDATE_PROFILE_BASE +
            " where username = ?";

    private static final String DEF_UPDATE_ADMIN = DEF_UPDATE_PROFILE_BASE +
            ", enabled = ?, locked = ?, password_expiry = ? " +
                " where username = ?";

    private static final String DEF_UPDATE_ADMIN_WITH_PASSWORD = DEF_UPDATE_PROFILE_BASE +
            ", enabled = ?, locked = ?, password_expiry = ?, password = ? " +
                " where username = ?";

    private static final String DEF_FIND_GROUP_ID_SQL =
            "select id from groups where group_name = ?";

    private static final String DEF_GET_ALL_GROUPS_SQL =
            "select g.group_name from groups g";

    private static final String DEF_INSERT_AUTHORITY_SQL =
            "insert into authorities (username, authority) values (?,?)";

    private static final String DEF_INSERT_GROUP_MEMBER_SQL =
            "insert into group_members (group_id, username) values (?,?)";

    private static final String DEF_DELETE_AUTHORITIES_SQL =
            "delete from authorities where username = ?";

    private static final String DEF_DELETE_GROUP_MEMBER_SQL =
            "delete from group_members where username = ?";

    private static final String DEF_DELETE_USERS_SQL =
            "delete from users where username = ?";

    /**
     * not used by Spring Security, and does not load groups or authorities - strictly for an admin list view of users
     */
	public List<RswUser> searchUsers(String usernameSearchTerm) {
        return getJdbcTemplate().query(DEF_SEARCH_USERS_QUERY, new String[] {usernameSearchTerm},
                new RswUserRowMapper());
	}

    public List<String> getAllGroups() {
        return getJdbcTemplate().queryForList(DEF_GET_ALL_GROUPS_SQL, String.class);
    }

	/**
     * create new user account with zero or more authorities directly specified;
     * user password encoder to encode, and apply initial values for expiry and other statuses
     * @param user
     */
	public void createUser(final RswUser user) {
        validateUserName(user.getUsername());
        passwordService.validatePassword(user.getPassword());

        getJdbcTemplate().update(DEF_CREATE_USER_SQL, ps -> {
            ps.setString(1, user.getUsername());
            ps.setString(2, passwordService.encodePassword(user.getPassword()));
            ps.setBoolean(3, user.isEnabled());
            ps.setBoolean(4, ! user.isAccountNonLocked());
            setOptionalTimestamp(ps, 5, getDefaultPasswordExpiry(user));
            ps.setString(6, user.getFirstName());
            setOptionalString(ps, 7, user.getMiddleInitial());
            ps.setString(8, user.getLastName());
            ps.setString(9, user.getEmailAddress());
            setOptionalString(ps, 10, user.getMobileNumber());
        });

        passwordService.recordPasswordHistory(user.getUsername(), user.getPassword());

        if (getEnableAuthorities()) {
            insertUserAuthorities(user);
        }
        else if (getEnableGroups()) {
            insertGroups(user);
        }
	}

    /**
     * Self update of user profile attributes (non-admin), including optional change password
     * Caller should set password to empty string if not intending to update, otherwise
     * a non-empty password is expected as plaintext with the intention to change the password.
     * No administrative attributes including groups or authorities are modified
     *
     * @param userUpdate
     */
	public void updateUserProfile(UserProfileUpdate userUpdate) {
	    updateProfile(userUpdate);

	    if (userUpdate.isChangePassword()) {
	       passwordService.changePassword(userUpdate.getUserName(), userUpdate.getOldPassword(),
                   userUpdate.getNewPassword());
        }
	}

    /**
     * Full update of user attributes, presumably by an administrator.
     * Optional change of password if caller sets password to something non-empty.  Password validation and
     * recording of password history occurs when a password is included
     * Groups and/or authorities are also updated
     * @param userUpdate
     */
    public void updateUserAdmin(RswUser userUpdate) {
	    if (! StringUtils.isEmpty(userUpdate.getPassword())) {
            passwordService.validateChangePassword(userUpdate.getUsername(), userUpdate.getPassword());
            updateProfileAdmin(userUpdate, true);
            passwordService.recordPasswordHistory(userUpdate.getUsername(), userUpdate.getPassword());
        } else {
            updateProfileAdmin(userUpdate, false);
        }

        if (getEnableAuthorities() && userUpdate.getAuthorities() != null && userUpdate.getAuthorities().size() > 0) {
            removeAllAuthorities(userUpdate.getUsername());
            insertUserAuthorities(userUpdate);
        }
        else if (getEnableGroups() && userUpdate.getGroups() != null && userUpdate.getGroups().size() > 0) {
            removeAllGroups(userUpdate.getUsername());
            insertGroups(userUpdate);
        }
    }

    /**
     * Returns true if userName exists in database.
     * @param userName
     * @return
     */
    public boolean userExists(String userName) {
        List<String> users = getJdbcTemplate().queryForList(DEF_USER_EXISTS_SQL, new String[] {userName}, String.class);

        return users.size() == 1;
    }

    /**
     * self change of password
     * @param userName
     * @param oldPassword
     * @param newPassword
     * @throws AuthenticationException
     */
    public void changePassword(final String userName, final String oldPassword, final String newPassword)
            throws AuthenticationException {
        passwordService.changePassword(userName, oldPassword, newPassword);
    }

    /**
     * Remove all traces of the specified userName
     * @param userName
     */
    public void deleteUser(String userName) {
        removeAllGroups(userName);
        removeAllAuthorities(userName);
        passwordService.removePasswordHistory(userName);
        removeUser(userName);
    }

    public void setPasswordService(PasswordService passwordService) {
        this.passwordService = passwordService;
    }

    /**
     * For testing only
     * @param userName
     * @param password
     * @return
     * @throws AuthenticationException
     */
    Authentication authenticate(String userName, String password) throws AuthenticationException {
        return passwordService.authenticate(userName, password);
    }

    /**
     * Run custom select query to get custom attributes from User table
     */
	@Override
	protected List<UserDetails> loadUsersByUsername(String username) {
        return getJdbcTemplate().query(DEF_USERS_BY_USERNAME_QUERY, new String[] {username},
                new UserDetailsRowMapper());
	}

    /**
     * not using user authorities directly - using group authorities
     * @param username
     * @return
     */
	@Override
    protected List<GrantedAuthority> loadUserAuthorities(String username) {
	    if (! getEnableAuthorities()) {
	        return new ArrayList<>();
        }
        return getJdbcTemplate().query(DEF_USER_AUTHORITIES_BY_USERNAME_QUERY, new String[] {username},
                new GrantedAuthorityRowMapper());
    }

    /**
     * will load group authorities and group names in one query later
     * @param username
     * @return
     */
    @Override
    protected List<GrantedAuthority> loadGroupAuthorities(String username) {
        if (! getEnableGroups()) {
            return new ArrayList<>();
        }
        return getJdbcTemplate().query(DEF_GROUP_AUTHORITIES_BY_USERNAME_QUERY, new String[] {username},
                new GrantedAuthorityRowMapper());
    }

    /**
     * Populate UserDetails from persisted data returned by loadUsersByUsername
     */
	@Override
	protected UserDetails createUserDetails(String username,
                                            UserDetails fetchedUser,
                                            List<GrantedAuthority> combinedAuthorities) {

	    Assert.isInstanceOf(RswUser.class, fetchedUser);
	    RswUser source = (RswUser) fetchedUser;

        RswUser newUser = new RswUser(source.getUsername(), source.getPassword(), source.isEnabled(),
                source.getPasswordExpiry(), ! source.isAccountNonLocked(), combinedAuthorities);

        List<RswGroup> groupNames = getJdbcTemplate().query(DEF_GROUPNAMES_BY_USERNAME_QUERY, new String[] {username},
                new RswGroupRowMapper());

        newUser.getGroups().addAll(groupNames);
        newUser.setFirstName(source.getFirstName())
                .setMiddleInitial(source.getMiddleInitial())
                .setLastName(source.getLastName())
                .setEmailAddress(source.getEmailAddress())
                .setMobileNumber(source.getMobileNumber());
        return newUser;
	}

    private void updateProfile(final UserProfileUpdate user) {
        getJdbcTemplate().update(DEF_UPDATE_PROFILE, ps -> {
            ps.setString(1, user.getFirstName());
            ps.setString(2, user.getMiddleInitial());
            ps.setString(3, user.getLastName());
            ps.setString(4, user.getEmailAddress());
            ps.setString(5, user.getMobileNumber());
            ps.setString(6, user.getUserName());
        });
    }

    private void updateProfileAdmin(final RswUser user, final boolean isChangePassword) {
        String updateSql = (isChangePassword ? DEF_UPDATE_ADMIN_WITH_PASSWORD : DEF_UPDATE_ADMIN);
        getJdbcTemplate().update(updateSql, ps -> {
            ps.setString(1, user.getFirstName());
            ps.setString(2, user.getMiddleInitial());
            ps.setString(3, user.getLastName());
            ps.setString(4, user.getEmailAddress());
            ps.setString(5, user.getMobileNumber());
            ps.setBoolean(6, user.isEnabled());
            ps.setBoolean(7, ! user.isAccountNonLocked());
            if (! isChangePassword) {
                setOptionalTimestamp(ps, 8, user.getPasswordExpiry());
                ps.setString(9, user.getUsername());
            } else {
                setOptionalTimestamp(ps, 8, getDefaultPasswordExpiry(user));
                ps.setString(9, passwordService.encodePassword(user.getPassword()));
                ps.setString(10, user.getUsername());
            }
        });
    }

    private void removeAllAuthorities(String userName) {
        getJdbcTemplate().update(DEF_DELETE_AUTHORITIES_SQL, userName);
    }

    private void insertUserAuthorities(UserDetails user) {
        Assert.isTrue(user.getAuthorities() != null);
        for (GrantedAuthority auth : user.getAuthorities()) {
            getJdbcTemplate().update(DEF_INSERT_AUTHORITY_SQL, user.getUsername(), auth.getAuthority());
        }
    }

    private void removeAllGroups(String userName) {
        getJdbcTemplate().update(DEF_DELETE_GROUP_MEMBER_SQL, userName);
    }

    private void insertGroups(RswUser user) {
        Assert.isTrue(user.getGroups() != null);
        for (RswGroup groupName : user.getGroups()) {
            addUserToGroup(user.getUsername(), groupName.toString());
        }
    }

    private void removeUser(String userName) {
        getJdbcTemplate().update(DEF_DELETE_USERS_SQL, userName);
    }

    private void addUserToGroup(final String username, final String groupName) {
        logger.debug("Adding user '" + username + "' to group '" + groupName + "'");
        final Integer id = findGroupId(groupName);
        getJdbcTemplate().update(DEF_INSERT_GROUP_MEMBER_SQL, ps -> {
            ps.setInt(1, id);
            ps.setString(2, username);
        });
    }

    private int findGroupId(String group) {
        return getJdbcTemplate().queryForObject(DEF_FIND_GROUP_ID_SQL, Integer.class, group);
    }

    private void validateUserName(String userName) {
        Assert.hasText(userName, "Username may not be empty or null");
        Assert.isTrue(! userExists(userName), "Username " + userName + " already exists");
    }

    private void setOptionalTimestamp(PreparedStatement ps, int paramNumber, LocalDateTime value) throws SQLException {
        if (value == null) {
            ps.setNull(paramNumber, Types.TIMESTAMP);
        } else {
            ps.setTimestamp(paramNumber, Timestamp.valueOf(value));
        }
    }

    private void setOptionalString(PreparedStatement ps, int paramNumber, String value) throws SQLException {
        if (value == null) {
            ps.setNull(paramNumber, Types.VARCHAR);
        } else {
            ps.setString(paramNumber, value);
        }
    }

    private LocalDateTime getDefaultPasswordExpiry(RswUser user) {
        if (user.getPasswordExpiry() == null) {
            return passwordService.getDefaultPasswordExpiry();
        }
       return user.getPasswordExpiry();
    }

}
