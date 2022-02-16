package com.security.server.http;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import javax.net.ssl.*;
import javax.swing.*;
import javax.swing.Timer;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.*;

public class Server {

    //Sessions are handled in a double hashmap. The first one called sessions handles the UUID to time assciation so that sessions can be tracked based on time.
    //The second one binds a user ID to a session ID and makes sure that the same user is using that session ID.
    //Another security implementation may require comparing the user's last well known IP address or MAC address so we can be sure the person is the same person.
    public static LinkedHashMap<UUID, Integer> sessions = new LinkedHashMap<>();
    public static LinkedHashMap<UUID, Integer> sids = new LinkedHashMap<>();

    public Server()throws Exception {
        HttpsServer server = HttpsServer.create(new InetSocketAddress(8000), 0);

        SSLContext sslContext = SSLContext.getInstance("TLS");

        // Initialise the keystore
        char[] password = "simulator".toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream fis = new FileInputStream("lig.keystore");

        ks.load(fis, password);

        // Set up the key manager factory
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, password);

        // Set up the trust manager factory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);

        // Set up the HTTPS context and parameters
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            public void configure(HttpsParameters params) {
                try {
                    // Initialise the SSL context
                    SSLContext c = SSLContext.getDefault();
                    SSLEngine engine = c.createSSLEngine();
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(engine.getEnabledCipherSuites());
                    params.setProtocols(engine.getEnabledProtocols());

                    // Get the default parameters
                    SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                    params.setSSLParameters(defaultSSLParameters);
                } catch (Exception ex) {
                    System.out.println("Failed to create HTTPS port");
                }
            }
        });


        server.createContext("/test", new Handler.HTTPDaemon());
        server.setExecutor(null); // creates a default executor
        server.start();

        ActionListener taskPerformer = evt -> sessionInvalidator();
        new Timer(5000, taskPerformer).start();
    }


    /*
    FRANTIC (TM) Security
    The FRANTIC security core is a simple session handler that records and maintains valid sessions from users.
    When a user is logged in, they should send special POSTS to keep the session alive. Otherwise, the session will time out
    after so long and return an INVALID command to the user via HTTP. This should prompt them to ask for another key.

    Every single transaction between the server and client should contain a session key and ID. Otherwise, how can we validate
    the legitimacy of the session? New ideas such as IP harvesting and machine ID should be implemented in order to prevent
    MITM attacks. This so far works fine.

    Frantic is not an acronym.
     */
    public static void sessionInvalidator() {
        long time = System.currentTimeMillis()/1000L;
        int i = 0;
        if (!sessions.isEmpty()){
            for (UUID uuid : sessions.keySet()){
                if (sessions.get(uuid) < time) {
                    sessions.remove(uuid);
                    sids.remove(uuid);
                    i++;
                }
            }
        }
        if (i > 0)
        System.out.println("Cleaned " + i + " sessions");
    }



    // String[] test = Status.split("\n");

    public static UUID addNewSession(int userID){
        UUID uuid = UUID.randomUUID();
        sessions.put(uuid, Math.toIntExact(System.currentTimeMillis()/1000L + 300)); //5 Minutes from now
        sids.put(uuid, userID);
        System.out.println("Entered session id " + uuid + " into table SESSIONS and SIDS");
        return uuid;
    }

    public static List<LinkedHashMap> getSessions() {
        List<LinkedHashMap> set = new LinkedList<>();
        if (sessions.isEmpty()) return null;
        set.add(sessions);
        set.add(sids);
        return set;
    }

}
