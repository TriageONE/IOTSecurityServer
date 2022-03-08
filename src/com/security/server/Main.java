package com.security.server;

import com.security.server.db.AuthServer;
import com.security.server.db.Operations;
import com.security.server.http.Server;

import javax.swing.Timer;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.util.*;

import static com.security.server.http.Server.sessionInvalidator;

public class Main {
    public static Connection connection;
    public static void main(String[] args) throws Exception {
	// write your code here


        AuthServer server = new AuthServer();
        connection = server.getConnection();
        System.out.println("Verifying Database...");
        if (!server.validate()){
            server.create();
            System.out.println("Created database");
        }
        ActionListener taskPerformer = evt -> sessionInvalidator();
        new Timer(5000, taskPerformer).start();
        System.out.println("Starting Server");
        Server httpServer = new Server();
        System.out.println("Started");


        /*
        Creating a server is fine for other authenticated clients doing critical
        service work on the database, but we need a login wrapper for managing
        generic users to log in and out of the service
         */
        //Server server = Server.createTcpServer().start();


        while (true){
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(System.in));

            // Reading data using readLine
            String command = reader.readLine().toLowerCase();

            switch (command) {
                case "sessions" -> {
                    List<LinkedHashMap> set = Server.getSessions();
                    if (set == null) System.out.println("No sessions found"); else
                    System.out.println("Session " + set.get(0).get(0) + " T" + set.get(0).get(1) + " U" + set.get(1).get(1) );
                }
                case "stop" -> {
                    System.out.println("System Exiting...");
                    server.stop();
                    System.exit(0);
                }
                default -> System.out.println("Command not recognized");
            }
        }
    }


}
