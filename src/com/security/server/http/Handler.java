package com.security.server.http;

import com.security.server.Main;
import com.security.server.auth.UserAuth;
import com.security.server.db.Operations;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.h2.engine.User;
import org.h2.security.auth.Authenticator;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.LinkOption;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

public class Handler {


    private static void respond(HttpExchange t, int code, String response) throws IOException {
        t.sendResponseHeaders(code, response.length());
        OutputStream os = t.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    private static String getBody(HttpExchange t) throws IOException {
        Reader reader = new BufferedReader(new InputStreamReader(t.getRequestBody(), Charset.forName(StandardCharsets.UTF_8.name())));
        StringBuilder textBuilder = new StringBuilder();
        int c;
        while ((c = reader.read()) != -1) {
            textBuilder.append((char) c);
        }

        return textBuilder.toString();
    }

    static class HTTPDaemon implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            String method = t.getRequestMethod();
            String response = null;
            if (Objects.equals(method, "POST")) {
                System.out.println("POST received");

                List<String> header = t.getRequestHeaders().get("request");
                String body = getBody(t);

                int code = 500;
                if (header != null) {
                    String type = header.get(0);
                    switch (type) {
                        case "authentication" -> {
                            String[] login = body.split("\\|");
                            //Take the two values and check them against a db
                            try {
                                ResultSet set = Operations.executeQuery("SELECT ID FROM AUTH WHERE USERNAME='" + login[0] + "' AND PASSWORD='" + login[1] + "'");
                                if (set == null) {
                                    response = "%INVALID";    //The response for authentication is -1 for both the session key generated and the user id. Nobody can have a UUID of -1.
                                } else {
                                    int id = Integer.parseInt(Operations.findSpecificResult(set, "ID"));
                                    code = 200;
                                    response = id + "\n" + Server.addNewSession(id);
                                }
                            } catch (SQLException e) {
                                e.printStackTrace();
                            }
                        }
                        case "cams" -> {
                            //User auth strings should come as follows:
                            //      <session_UUID> | <UID>

                            //Should make a validator for this because if we feed it a malformed string then this may cause issues
                            String[] session = body.split("\\|"); // Gets the first line and splits it up into the session ID and the user
                            UUID sessionKey = UUID.fromString(session[1]); //The first line should be the session key associated with the user
                            int userID = Integer.parseInt(session[0]);

                            System.out.println("USER " + userID + ", SESSION " + sessionKey);
                            //We need to make sure the user is valid for this request.
                            UserAuth user = new UserAuth(userID, sessionKey);
                            if (user.validate()) {
                                //The list of devices will come from ownership of ids within cameras entries. Each device will have a unique identifier, 8 characters long with 24+10 possible characters per slot.
                                //This gives us almost 1.78 trillion different devices possible. I think thats enough.
                                //The clob is delimited by line breaks. splitting it up by that should be enough
                                //response = Operations.executeQuery("SELECT ");
                                ResultSet resultSet;
                                try {
                                    resultSet = Operations.executeQuery("SELECT NAME, UUID FROM CAMERAS WHERE OWNER='" + user.getUserID() + "'");
                                } catch (SQLException e) {
                                    e.printStackTrace();
                                    response = "";
                                    code = 200;
                                    break;
                                }
                                assert resultSet != null;
                                //What this should look like is for every camera, there is a name and UUID. These values are split with a pipe. The entire cameras are split with line breaks
                                try {
                                    response = Operations.findAllResults(resultSet);
                                    code = 200;
                                } catch (SQLException e) {
                                    e.printStackTrace();
                                    response = "";
                                }

                            } else {
                                //respond session invalid
                                code = 511;
                                response = "%INVALID";
                            }

                        }
                        case "checkin" -> {
                            //The camera must check in with the server.
                            //In order to check in, the camera has to have a serial number, and a string code.

                            //In the future, cameras should have their own unique login so that they can authenticate themselves. Right now, if you provide all the right info, you could spoof this.
                            InetSocketAddress address = t.getRemoteAddress();
                            Date date = new Date();
                            date.setTime(System.currentTimeMillis());

                            String[] splitbody = body.split("\\|");

                            String serial = splitbody[0];
                            String status = splitbody[1];
                            String authenticator = splitbody[2];

                            try {
                                Operations.executeQuery("UPDATE CAMERAS(LAST_IP, LAST_STATUS) VALUES('" + address + "', '" + status + "') WHERE UUID='" + serial + " AND AUTHENTICATOR='" + authenticator + "'");
                            } catch (SQLException e) {
                                e.printStackTrace();
                            }



                        }
                        case "keepalive" -> {
                            String sessionKey = body;



                        }
                    }
                }

                assert header != null;
                System.out.println(body + "\nHEADER: " + header.get(0) + ", LENGTH:" + header.size());
                assert response != null;
                respond(t, code, response);

            }
            if (Objects.equals(method, "GET")){
                System.out.println("GET received, sending code");
                response = "200 OK";
                respond(t, 200, response);
            }
            //Form the string to be sent
        }
    }
}
