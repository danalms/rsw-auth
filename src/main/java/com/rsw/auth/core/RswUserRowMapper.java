package com.rsw.auth.core;

import com.rsw.auth.domain.RswUser;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.authority.AuthorityUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;

/**
 * Created by DAlms on 11/26/16.
 *
 * does NOT load any authorities
 */
public class RswUserRowMapper implements RowMapper<RswUser> {
    @Override
    public RswUser mapRow(ResultSet rs, int rowNum) throws SQLException {
        String username = rs.getString("username");
        String password = rs.getString("password");
        String firstName = rs.getString("first_name");
        String middleInitial = rs.getString("middle_initial");
        String lastName = rs.getString("last_name");
        String emailAddress = rs.getString("email_address");
        String mobileNumber = rs.getString("mobile_number");
        boolean enabled = rs.getBoolean("enabled");
        boolean locked = rs.getBoolean("locked");
        Timestamp passwordExpiryTs = (Timestamp) rs.getObject("password_expiry");
        LocalDateTime passwordExpiry = (passwordExpiryTs !=null ? passwordExpiryTs.toLocalDateTime() : null);

        RswUser user = new RswUser(username, password, enabled, passwordExpiry, locked, AuthorityUtils.NO_AUTHORITIES);
        return user.setFirstName(firstName)
                .setMiddleInitial(middleInitial)
                .setLastName(lastName)
                .setEmailAddress(emailAddress)
                .setMobileNumber(mobileNumber);
    }
}
