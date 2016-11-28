package com.rsw.auth.core;

import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Created by DAlms on 11/26/16.
 */
public class GrantedAuthorityRowMapper implements RowMapper<GrantedAuthority> {
    @Override
    public GrantedAuthority mapRow(ResultSet rs, int rowNum) throws SQLException {
        String authority = rs.getString("authority");
        return new SimpleGrantedAuthority(authority);
    }
}
