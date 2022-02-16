package com.security.server.db;


import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import static com.security.server.Main.connection;

public class Operations {

    public static String findSpecificResult(ResultSet resultSet, String label) throws SQLException {                    //Primarily meant if the result should be one specific datum. Will return null if no results are found.
        if (resultSet != null) {
            if(resultSet.next()){
                return resultSet.getString(label);
            }
        }
        return null;
    }

    public static String findAllResults(ResultSet resultSet) throws SQLException {                                      //Will find all results for broader searches in a database. Is more extendable than findSpecificResult() but slower because of the string builder
        String fullStatement = "";
        if (resultSet != null){
            while(resultSet.next()){
                int i = 1;
                for(;;) {
                    try {
                        fullStatement = fullStatement.concat(resultSet.getString(i)) + "|";
                    } catch (SQLException ignored) {
                        break;
                    }
                    i++;
                }
                fullStatement = fullStatement.concat("\n");
            }
            return fullStatement;
        }
        return null;
    }

    public static ResultSet executeQuery( String sql) throws SQLException {

        return connection.createStatement().executeQuery(sql);
    }

    public static String createNewSerial(){
        //The serial should contain letters and numbers in a format like XXXX-XXXX-XXXX
        char[] characters = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
        char[] uuid = UUID.randomUUID().toString().toCharArray();
        StringBuilder serial = new StringBuilder();
        int counter = 0;
        for (int i = 0; i <= 11; i++){
            int b = (byte) (Integer.parseInt(String.valueOf(uuid[counter] + uuid[counter + 1]))) & 0xFF;
            counter = counter + 2;
            if (i%4 == 0 && i > 0) serial.append("-");
            serial.append(characters[b - ((b / 36) * 36)]);  //Overflow formula. When fed a number greater than 36, generates a number between 0 and 35
        }
        return serial.toString();
    }
}
