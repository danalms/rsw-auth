package com.rsw.auth.core;

import static org.junit.Assert.*;
import com.rsw.auth.domain.RswGroup;
import com.rsw.auth.domain.RswUser;
import com.rsw.auth.domain.UserProfileUpdate;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

@RunWith(SpringRunner.class)
@SpringBootTest
@Transactional
public class RswUserDetailsServiceIGTest {

    private static final Logger LOG = LoggerFactory.getLogger(RswUserDetailsService.class);

	@Autowired
    RswUserDetailsService userDetailsService;

	@Autowired
    JdbcTemplate testJdbcTemplate;

	@Test
	public void createUser_happy() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
		userDetailsService.createUser(user);

        RswUser puser = getPersistedUser(user.getUsername());
        LOG.info("Encrypted password: '{}'", puser.getPassword());
        assertTrue(puser.isAccountNonExpired());
        assertTrue(puser.isAccountNonLocked());
        assertTrue(puser.isCredentialsNonExpired());
        assertTrue(puser.getPasswordExpiry() != null && puser.getPasswordExpiry().isAfter(LocalDateTime.now()));

        // verify groups inserted
    	List<RswGroup> pgroups = puser.getGroups();
        assertTrue(pgroups.size() == 1);
        assertTrue(pgroups.get(0).equals(RswGroup.SYSTEM_ADMIN));
	}

    @Test
    public void createUser_expired() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", true, LocalDateTime.now(), false, RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        RswUser puser = getPersistedUser(user.getUsername());
        LOG.info("Encrypted password: '{}'", puser.getPassword());
        assertTrue(puser.isAccountNonExpired());
        assertTrue(puser.isAccountNonLocked());
        assertFalse(puser.isCredentialsNonExpired());
        assertTrue(puser.getPasswordExpiry() != null && puser.getPasswordExpiry().isBefore(LocalDateTime.now()));
    }

    @Test
    public void updateUserProfile_happy() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        UserProfileUpdate updatedUser = getUserUpdate("joetest");
        userDetailsService.updateUserProfile(updatedUser);

        RswUser puser = getPersistedUser(user.getUsername());
        assertEquals(updatedUser.getFirstName(), puser.getFirstName());
        assertEquals(updatedUser.getMiddleInitial(), puser.getMiddleInitial());
        assertEquals(updatedUser.getLastName(), puser.getLastName());
        assertEquals(updatedUser.getEmailAddress(), puser.getEmailAddress());
        assertEquals(updatedUser.getMobileNumber(), puser.getMobileNumber());
    }

    @Test
    public void updateUserProfile_password() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        UserProfileUpdate updatedUser = getUserUpdatePassword("joetest", user.getPassword(), "UpP@ssword1");
        userDetailsService.updateUserProfile(updatedUser);

        RswUser puser = getPersistedUser(user.getUsername());
        assertEquals(updatedUser.getFirstName(), puser.getFirstName());
        assertEquals(updatedUser.getMiddleInitial(), puser.getMiddleInitial());
        assertEquals(updatedUser.getLastName(), puser.getLastName());
        assertEquals(updatedUser.getEmailAddress(), puser.getEmailAddress());
        assertEquals(updatedUser.getMobileNumber(), puser.getMobileNumber());

        userDetailsService.authenticate(user.getUsername(), updatedUser.getNewPassword());
    }

	@Test(expected = AuthenticationException.class)
	public void changePassword_authFail() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        // incorrect old password - authentication should fail
        userDetailsService.changePassword(user.getUsername(), "fail", user.getPassword());
    }

    @Test
    public void changePassword_noReuse() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        // try to reuse previous password
        Exception exc = null;
        try {
            userDetailsService.changePassword(user.getUsername(), user.getPassword(), user.getPassword());
        } catch (IllegalArgumentException e) {
            exc = e;
        }
        assertTrue(exc != null);
        assertTrue(exc.getMessage().matches("Cannot reuse an old password"));
    }

    @Test
    public void changePassword_minimumLength() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        Exception exc = null;
        try {
            // new password length < 5
            userDetailsService.changePassword(user.getUsername(), user.getPassword(), "aB9-");
        } catch (IllegalArgumentException e) {
            exc = e;
        }
        assertTrue(exc != null);
        assertTrue(exc.getMessage().matches("Password doesn't meet requirements"));
    }

    @Test
    public void changePassword_maximumLength() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        Exception exc = null;
        try {
            // new password length > 11
            userDetailsService.changePassword(user.getUsername(), user.getPassword(), "MyP@ssw0rd12");
        } catch (IllegalArgumentException e) {
            exc = e;
        }
        assertTrue(exc != null);
        assertTrue(exc.getMessage().matches("Password doesn't meet requirements"));
    }

    @Test
    public void changePassword_noUpper() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        Exception exc = null;
        try {
            userDetailsService.changePassword(user.getUsername(), user.getPassword(), "abcde-123");
        } catch (IllegalArgumentException e) {
            exc = e;
        }
        assertTrue(exc != null);
        assertTrue(exc.getMessage().matches("Password doesn't meet requirements"));
    }

    @Test
    public void changePassword_noLower() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        Exception exc = null;
        try {
            userDetailsService.changePassword(user.getUsername(), user.getPassword(), "ABCDE-123");
        } catch (IllegalArgumentException e) {
            exc = e;
        }
        assertTrue(exc != null);
        assertTrue(exc.getMessage().matches("Password doesn't meet requirements"));
    }

    @Test
    public void changePassword_noDigit() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        Exception exc = null;
        try {
            userDetailsService.changePassword(user.getUsername(), user.getPassword(), "abCDE-");
        } catch (IllegalArgumentException e) {
            exc = e;
        }
        assertTrue(exc != null);
        assertTrue(exc.getMessage().matches("Password doesn't meet requirements"));
    }

    @Test
    public void changePassword_noSpecial() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        Exception exc = null;
        try {
            userDetailsService.changePassword(user.getUsername(), user.getPassword(), "abCDE123");
        } catch (IllegalArgumentException e) {
            exc = e;
        }
        assertTrue(exc != null);
        assertTrue(exc.getMessage().matches("Password doesn't meet requirements"));
    }

    @Test
    public void changePassword_happy() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        // password #2
        userDetailsService.changePassword(user.getUsername(), user.getPassword(), "abCDE-123");
    }

    @Test
    public void changePassword_recycle() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        Exception exc = null;
        // password #2
		userDetailsService.changePassword(user.getUsername(), "MyP@ssw0rd1", "abCD-2");
        // password #3
        userDetailsService.changePassword(user.getUsername(), "abCD-2", "abCD-3");
        // password #4
        userDetailsService.changePassword(user.getUsername(), "abCD-3", "abCD-4");

        // try to reuse 1st password now
        try {
            userDetailsService.changePassword(user.getUsername(), "abCD-4", "MyP@ssw0rd1");
        } catch (IllegalArgumentException e) {
            exc = e;
        }
        assertTrue(exc != null);
        assertTrue(exc.getMessage().matches("Cannot reuse an old password"));

        // password #5
        userDetailsService.changePassword(user.getUsername(), "abCD-4", "abCD-5");

        // password #6: now should be able to reuse since the last 4 were different
        userDetailsService.changePassword(user.getUsername(), "abCD-5", "MyP@ssw0rd1");
	}

	@Test
	public void userExists() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
		userDetailsService.createUser(user);

        assertTrue(userDetailsService.userExists(user.getUsername()));

        Exception exc = null;
        try {
    		userDetailsService.createUser(user);
        }
        catch (Exception e) {
        	exc = e;
        }
        assertTrue(exc != null);
        assertTrue(exc.getMessage().matches("Username " + user.getUsername() + " already exists"));
	}

	@Test
	public void loadUserByUsername() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
		userDetailsService.createUser(user);

        // update to set new password and set password expiry to now
		RswUser updUser = getUser(user.getUsername(), "MyP@ssw0rd3", true, LocalDateTime.now(), false,
                RswGroup.SYSTEM_ADMIN);
        userDetailsService.updateUserAdmin(updUser);

        RswUser puser = (RswUser) userDetailsService.loadUserByUsername(user.getUsername());
        assertTrue(puser != null);
        assertFalse(puser.isCredentialsNonExpired());
        assertTrue(puser.getGroups().size() == 1);
        assertTrue(puser.getGroups().get(0).equals(RswGroup.SYSTEM_ADMIN));
	}

	@Test
	public void deleteUser() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
		userDetailsService.createUser(user);

        RswUser puser = (RswUser) userDetailsService.loadUserByUsername(user.getUsername());
        assertTrue(puser != null);

        userDetailsService.deleteUser(user.getUsername());

        assertFalse(userDetailsService.userExists(user.getUsername()));
	}

	@Test
	public void authenticate_retrySuccess() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        Exception exc = null;
        try {
            userDetailsService.authenticate(user.getUsername(), "fail");
        } catch (BadCredentialsException e) {
            exc = e;
        }
        assertNotNull(exc);

        exc = null;
        try {
            userDetailsService.authenticate(user.getUsername(), user.getPassword());
        } catch (BadCredentialsException e) {
            exc = e;
        }
        assertNull(exc);
    }

    @Test(expected = DisabledException.class)
    public void updateUserAdmin_authenticateDisabled() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        // disable account
        RswUser updUser = getUser(user.getUsername(), "", false, null, false, RswGroup.SYSTEM_ADMIN);
        userDetailsService.updateUserAdmin(updUser);
        userDetailsService.authenticate(user.getUsername(), user.getPassword());
    }

    @Test(expected = LockedException.class)
    public void updateUserAdmin_authenticateLocked() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        // lock account
        RswUser updUser = getUser(user.getUsername(), "", true, null, true, RswGroup.SYSTEM_ADMIN);
        userDetailsService.updateUserAdmin(updUser);
        userDetailsService.authenticate(user.getUsername(), user.getPassword());
    }

    @Test(expected = CredentialsExpiredException.class)
    public void updateUserAdmin_authenticateExpired() throws Exception {
        RswUser user = getUser("joetest", "MyP@ssw0rd1", RswGroup.SYSTEM_ADMIN);
        userDetailsService.createUser(user);

        // update with new password and password expiry to now
        RswUser updUser = getUser(user.getUsername(), "MyP@ssw0rd3", true, LocalDateTime.now(), false,
                RswGroup.SYSTEM_ADMIN);
        userDetailsService.updateUserAdmin(updUser);
        userDetailsService.authenticate(updUser.getUsername(), updUser.getPassword());
	}

    private RswUser getUser(String userName, String password, RswGroup ... groups) {
	    // no password expiration
	    RswUser user = new RswUser(userName, password, true, null, false, Arrays.asList(groups));
	    return user.setFirstName("Test").setLastName("User").setEmailAddress("test@example.com");
    }

    private RswUser getUser(String userName, String password, boolean enabled, LocalDateTime passwordExpiry,
                                boolean locked, RswGroup ... groups) {
        RswUser user = new RswUser(userName, password, enabled, passwordExpiry, locked, Arrays.asList(groups));
        return user.setFirstName("Test").setLastName("User").setEmailAddress("test@example.com");
    }

    private UserProfileUpdate getUserUpdate(String userName) {
        UserProfileUpdate update = new UserProfileUpdate(userName);
        update.setFirstName("UTest").setMiddleInitial("T").setLastName("UUser")
                .setEmailAddress("utest@example.com").setMobileNumber("6125551212");
        return update;
    }

    private UserProfileUpdate getUserUpdatePassword(String userName, String oldPassword, String newPassword) {
        UserProfileUpdate update = new UserProfileUpdate(userName);
        update.setFirstName("UTest").setMiddleInitial("T").setLastName("UUser")
                .setEmailAddress("utest@example.com").setMobileNumber("6125551212");
        return update.setOldPassword(oldPassword).setNewPassword(newPassword);
    }

    private RswUser getPersistedUser(String userName) {
        List<RswUser> users = testJdbcTemplate.query(RswUserDetailsService.DEF_USERS_BY_USERNAME_QUERY,
                new String[]{userName}, new RswUserRowMapper());
        assertTrue(users.size() == 1);
        RswUser user = users.get(0);
        user.setGroups(getPersistedRswGroups(userName));
        return user;
    }

    private List<RswGroup> getPersistedRswGroups(String userName) {
    	return testJdbcTemplate.query(RswUserDetailsService.DEF_GROUPNAMES_BY_USERNAME_QUERY, new String[] {userName},
                new RswGroupRowMapper());
    }

}
