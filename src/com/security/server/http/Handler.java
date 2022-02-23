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
                response = "%MISUNDERSTOOD";
                if (header != null) {
                    String type = header.get(0);
                    switch (type) {
                        case "authentication" -> {
                            String[] login = body.split("\\|");
                            //Take the two values and check them against a db
                            try {
                                ResultSet set = Operations.executeQuery("SELECT ID FROM AUTH WHERE USERNAME='" + login[0] + "' AND PASSWORD='" + login[1] + "'");
                                if (set == null) {
                                    System.out.println("AUTHENTICATION: Null set, returning INVALID");
                                    response = "%INVALID";    //The response for authentication is -1 for both the session key generated and the user id. Nobody can have a UUID of -1.
                                } else {
                                    System.out.println("AUTHENTICATION: Found ID AND Session");
                                    int id = Integer.parseInt(Operations.findSpecificResult(set, "ID"));
                                    code = 200;
                                    response = id + "\n" + Server.addNewSession(id);
                                    System.out.println("Sending response " + response + " || CODE " + code);
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
                                    resultSet = Operations.executeQuery("SELECT UUID, NAME FROM CAMERAS WHERE OWNER='" + user.getUserID() + "'");
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
                                    System.out.println("CAMS SENT: \n" + response);

                                    code = 200;
                                } catch (SQLException e) {
                                    e.printStackTrace();
                                    response = "";
                                }

                            } else {
                                //respond session invalid
                                code = 511;
                                response = "%INVALID";
                                System.out.println("Invalid session ID: " + user.getSessionKey());
                            }

                        }
                        case "status" -> {
                            //The idea is to ask the server here for a status on a list of cameras
                            //The list is separated by a line break
                            //The first line should be the session key
                            //Next should be a list of cams

                            String[] split = body.split("\n");

                            String session_key = split[0].split("\\|")[0];
                            int id = Integer.parseInt(split[0].split("\\|")[1]);
                            //key|id
                            //Check if session key valid or not
                            UserAuth user = new UserAuth(id, session_key);
                            if (!user.validate()) {
                                response = "%INVALID";
                                code = 511;
                                System.err.println("User auth failed for " + id);
                                break;
                            }
                            //The subset of cameras the user wishes to query
                            LinkedList<String> serials = new LinkedList<>(Arrays.asList(split).subList(1, split.length + 1));

                            //The subset of filtered valid cameras that the user specified above, and has confirmed ownership of should be a modified Serials list
                            //Find all of these cameras and their status
                            ResultSet set;
                            try {
                                set = Operations.executeQuery("SELECT UUID FROM CAMERAS WHERE OWNER=" + user.getUserID());
                                LinkedList<String> results = new LinkedList<>(Arrays.asList(Operations.findAllResults(set).split("\n")));
                                serials.removeIf(serial -> !results.contains(serial));
                            } catch (SQLException e) {
                                e.printStackTrace();
                            }
                            //The now valid list of serials can now be queried for their statuses and returned to the client
                            StringBuilder complingResponse = new StringBuilder();
                            for(String serial : serials) {
                                try {
                                    set = Operations.executeQuery("SELECT STATUS FROM CAMERAS WHERE UUID='" + serial + "'");
                                    complingResponse.append(serial).append("|").append(Operations.findSpecificResult(set, "STATUS")).append("\n");
                                } catch (SQLException e) {
                                    e.printStackTrace();
                                }
                            }
                            response = complingResponse.toString();
                            code = 201;
                        }
                        case "checkin" -> {
                            //The camera must check in with the server.
                            //In order to check in, the camera has to have a serial number, and a string code.

                            //In the future, cameras should have their own unique login so that they can authenticate themselves. Right now, if you provide all the right info, you could spoof this.
                            System.out.println("Checkin incoming");
                            InetSocketAddress address = t.getRemoteAddress();
                            Date date = new Date();
                            date.setTime(System.currentTimeMillis());

                            String[] splitbody = body.split("\\|");

                            String serial = splitbody[0];
                            String status = splitbody[1];
                            String authenticator = splitbody[2];

                            try {
                                ResultSet set = Operations.executeQuery("SELECT AUTHENTICATOR FROM CAMERAS WHERE UUID='" + serial + "'");

                                if(set == null){
                                    code = 404;
                                    response = "%NOT_FOUND";
                                    System.err.println("Base not found: " + serial);
                                    break;
                                }
                                String remoteAuth = Operations.findSpecificResult(set, "AUTHENTICATOR");

                                if(!remoteAuth.equals(authenticator)){
                                    code = 401;
                                    response = "%INVALID";
                                    System.err.println("Auth failure, " + remoteAuth + " vs " + authenticator);
                                    break;
                                }
                                Operations.executeAction(
                                "UPDATE CAMERAS " +
                                    "SET LAST_IP='" + address +
                                    "', LAST_STATUS='" + status +
                                    "' WHERE UUID='" + serial +
                                    "' AND AUTHENTICATOR='" + authenticator + "';");

                                System.out.println("Updated base " + serial + " with status " + status);
                                code = 201;
                                response = "%UPDATED";
                            } catch (SQLException e) {
                                e.printStackTrace();
                            }

                        }
                        case "keepalive" -> {
                            //In order to keep the connection alive, the user must send back their session
                            // key, id and a random set of data separated by a pipe character
                            String[] sessionKey = body.split("\\|");
                            boolean alive = Server.requestKeepalive(sessionKey[0], Integer.parseInt(sessionKey[0]));
                            if (alive) {
                                response = "%UPDATED";
                                code = 202;
                            } else {
                                response = "NO_SESSION";
                                code = 401;
                            }
                        }
                        case "stream" -> {
                            //Data format should be in format id | session_key | camera_ID
                            System.out.println("Stream requested " + body);
                            String[] requestBody = body.split("\\|");

                            int userID = Integer.parseInt(requestBody[0]);
                            String session_key = requestBody[1];
                            String cameraID = requestBody[2];

                            //Validate user

                            UserAuth user = new UserAuth(userID, session_key);

                            if (!user.validate()){
                                System.out.println("User not valid: " + session_key + ", " + userID);
                                response = "%INVALID";
                                break;
                            }

                            try {
                                ResultSet set = Operations.executeQuery("SELECT LAST_IP FROM CAMERAS WHERE UUID='" + cameraID + "' AND OWNER=" + userID);
                                System.out.println("SELECT LAST_IP FROM CAMERAS WHERE UUID='" + cameraID + "' AND OWNER=" + userID);
                                if (set == null) {
                                    response = "%BAD_REQUEST";
                                    System.out.println("Bad request");
                                    code = 511;
                                } else {
                                    System.out.println(set);
                                    response = Operations.findSpecificResult(set, "LAST_IP");
                                    System.out.println(response + ": Last IP");
                                    code = 200;
                                }
                            } catch (SQLException e) {
                                e.printStackTrace();
                            }

                        }
                    }
                }

                assert header != null;
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
