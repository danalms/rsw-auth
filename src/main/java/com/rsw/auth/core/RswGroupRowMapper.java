package com.rsw.auth.core;

import com.rsw.auth.domain.RswGroup;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Created by DAlms on 11/26/16.
 */
public class RswGroupRowMapper implements RowMapper<RswGroup> {
    @Override
    public RswGroup mapRow(ResultSet rs, int rowNum) throws SQLException {
        String groupName = rs.getString("group_name");
        return RswGroup.valueOf(groupName);
    }
}
