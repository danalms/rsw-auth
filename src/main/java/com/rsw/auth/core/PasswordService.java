package com.rsw.auth.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.PostConstruct;


/**
 * Delegate to handle password management
 * This class is explicitly configured as a bean in the SecurityConfig and therefore is not @Service annotated
 */
@Transactional
public class PasswordService {

    private static final Logger LOGGER = LoggerFactory.getLogger(PasswordService.class);

    private JdbcTemplate jdbcTemplate;
    private AuthenticationManager authenticationManager;
    private PasswordEncoder passwordEncoder;
    private Integer passwordExpiryDays;
    private Integer passwordRecycleSpan;
    private String passwordFormatRegEx;
    private Pattern passwordPattern;

    private static final String DEF_CHANGE_PASSWORD_SQL =
            "update spring.users set password = ?, password_expiry = ? where username = ?";

    private static final String DEF_FIND_PASSWORD_HISTORY_SQL =
            "select password from spring.password_history where username = ? order by changed_date DESC";

    private static final String DEF_INSERT_PASSWORD_HISTORY_SQL =
            "insert into spring.password_history (username, password, changed_date) values(?,?,?)";

    private static final String DEF_DELETE_PASSWORD_HISTORY_SQL =
            "delete from spring.password_history where username = ?";

    private static final String DEF_DELETE_PERSISTENT_LOGINS_SQL =
            "delete from spring.persistent_logins where username = ?";


    @PostConstruct
    public void onPostConstruct() {
    	if (passwordFormatRegEx != null) {
    		passwordPattern = Pattern.compile(passwordFormatRegEx);
    	}
    }

    /**
     * Intended for a user changing their own password.  No other attributes are modified.
     * Requires old password to pass authentication.
     * @param userName
     * @param oldPassword
     * @param newPassword
     * @throws AuthenticationException
     */
	void changePassword(final String userName, final String oldPassword, final String newPassword)
			throws AuthenticationException {
        authenticate(userName, oldPassword);
        validateChangePassword(userName, newPassword);

        jdbcTemplate.update(DEF_CHANGE_PASSWORD_SQL, ps -> {
            ps.setString(1, passwordEncoder.encode(newPassword));
            setOptionalTimestamp(ps, 2, getDefaultPasswordExpiry());
            ps.setString(3, userName);
        });
        recordPasswordHistory(userName, newPassword);
	}

    /**
     * for convenience, returns current password if validations pass
     * @param userName
     * @param password
     * @return
     */
    void validateChangePassword(String userName, String password) {
        validatePassword(password);

        if (passwordRecycleSpan == null) {
            return;
        }

        List<String> passwords = new ArrayList<>();
        // get password history
        passwords.addAll(jdbcTemplate.queryForList(DEF_FIND_PASSWORD_HISTORY_SQL, new String[] {userName},
                String.class));

        for (int ix = 0; ix < passwordRecycleSpan && ix < passwords.size(); ix++) {
            String encodedPassword = passwords.get(ix);
            Assert.isTrue(! passwordEncoder.matches(password, encodedPassword), "Cannot reuse an old password");
        }
    }

    void validatePassword(String password) {
        Assert.hasText(password, "Password may not be empty or null");
        if (passwordPattern != null) {
            Matcher matcher = passwordPattern.matcher(password);
            Assert.isTrue(matcher.matches(), "Password doesn't meet requirements");
        }
    }

	String encodePassword(String clearTextPassword) {
        return passwordEncoder.encode(clearTextPassword);
    }

    LocalDateTime getDefaultPasswordExpiry() {
    	if (passwordExpiryDays == null) {
            // passwords don't expire
    		return null;
    	}
    	LocalDateTime now = LocalDateTime.now();
    	return now.plusDays(passwordExpiryDays);
    }

    void recordPasswordHistory(final String userName, final String clearPassword) {
        final String encryptedPassword = passwordEncoder.encode(clearPassword);
        final LocalDateTime now = LocalDateTime.now();
        jdbcTemplate.update(DEF_INSERT_PASSWORD_HISTORY_SQL, ps -> {
            ps.setString(1, userName);
            ps.setString(2, encryptedPassword);
            ps.setTimestamp(3, Timestamp.valueOf(now));
        });
    }

    void removePasswordHistory(String userName) {
        jdbcTemplate.update(DEF_DELETE_PASSWORD_HISTORY_SQL, userName);
        jdbcTemplate.update(DEF_DELETE_PERSISTENT_LOGINS_SQL, userName);
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public PasswordService setJdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        return this;
    }

    public PasswordService setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        return this;
    }

    public void setPasswordExpiryDays(Integer passwordExpiryDays) {
        this.passwordExpiryDays = passwordExpiryDays;
    }

    public void setPasswordRecycleSpan(Integer passwordRecycleSpan) {
        this.passwordRecycleSpan = passwordRecycleSpan;
    }

    public void setPasswordFormatRegEx(String passwordFormatRegEx) {
        this.passwordFormatRegEx = passwordFormatRegEx;
    }

    /**
     * for internal use and testing only
     * @param userName
     * @param password
     * @return
     * @throws AuthenticationException (DisabledException, LockedException, BadCredentialsException)
     */
    Authentication authenticate(String userName, String password) throws AuthenticationException {
        Authentication token = new UsernamePasswordAuthenticationToken(userName, password);
        return authenticationManager.authenticate(token);
    }

    private void setOptionalTimestamp(PreparedStatement ps, int paramNumber, LocalDateTime value) throws SQLException {
        if (value == null) {
            ps.setNull(paramNumber, Types.TIMESTAMP);
        } else {
            ps.setTimestamp(paramNumber, Timestamp.valueOf(value));
        }
    }

}
