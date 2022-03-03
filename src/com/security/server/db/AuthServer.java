package com.security.server.db;

import java.sql.*;
import java.util.Objects;

import static com.security.server.db.Operations.findSpecificResult;

public class AuthServer {
    Connection connection;

    public AuthServer() throws SQLException {
        connection = DriverManager.getConnection("jdbc:h2:./test", "sa", "");
    }

    public boolean validate() throws SQLException {
        //The database is a simple one, that only has a table of users and their salted passwords.
        //TABLE AUTH
        //      COL USERS       COL PASSWORDS
        System.out.println("Querying tables..");
        Statement statement = connection.createStatement();
        statement.execute("CREATE TABLE IF NOT EXISTS AUTH(ID IDENTITY NOT NULL PRIMARY KEY, USERNAME VARCHAR(64), PASSWORD VARCHAR(128))");
        statement.execute("CREATE TABLE IF NOT EXISTS CAMERAS(UUID CHAR(14) NOT NULL, NAME VARCHAR(128) NOT NULL, LAST_IP VARCHAR(38), LAST_STATUS CHAR(8), OWNER BIGINT, AUTHENTICATOR VARCHAR(20) NOT NULL)");

        System.out.println("Querying values..");

        ResultSet resultSet = statement.executeQuery("SELECT USERNAME FROM AUTH WHERE ID=0");

        if (!Objects.equals(findSpecificResult(resultSet, "USERNAME"), "DEFAULT")){
            System.out.println("Failed Validation 0");
            return false;
        }

        resultSet = statement.executeQuery("SELECT UUID FROM CAMERAS WHERE UUID='0000-0000-0000'");

        if (!Objects.equals(findSpecificResult(resultSet, "UUID"), "0000-0000-0000")){
            System.out.println("Failed Validation 1");
            return false;
        }
        System.out.println("Verification success");

        return true;
    }

    public void create(){
        Statement statement = null;
        try {
            System.out.println("Creating Database..");

            statement = connection.createStatement();
            statement.execute("CREATE TABLE IF NOT EXISTS AUTH(ID IDENTITY NOT NULL PRIMARY KEY, USERNAME VARCHAR(64), PASSWORD VARCHAR(128))");
            statement.execute("MERGE INTO AUTH(ID, USERNAME, PASSWORD) VALUES(0, 'DEFAULT', 'DEFAULT')");
            System.out.println("Merged default user");

            statement.execute("CREATE TABLE IF NOT EXISTS CAMERAS(UUID CHAR(14) NOT NULL, NAME VARCHAR(128) NOT NULL, LAST_IP VARCHAR(38), LAST_STATUS CHAR(8), OWNER BIGINT, AUTHENTICATOR VARCHAR(20) NOT NULL)");
            statement.execute("INSERT INTO CAMERAS(UUID, NAME, LAST_IP, LAST_STATUS, OWNER, AUTHENTICATOR) VALUES('0000-0000-0000', 'dumb base station', '0.0.0.0', 'DEADCAMS', 0, 'defaultbasestation')");
            System.out.println("Merged Default Camera");

        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public Connection getConnection(){
        return this.connection;
    }

    public void stop() throws SQLException {
        connection.close();
    }

}
