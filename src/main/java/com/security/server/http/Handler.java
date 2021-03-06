package com.security.server.http;

import com.security.server.Main;
import com.security.server.auth.UserAuth;
import com.security.server.db.Operations;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;

import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
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

    static class StreamPuncherDaemon implements HttpHandler {
        @Override
        public void handle(HttpExchange t){
            String method = t.getRequestMethod();
            String response;
            int code;

        }
    }

    static class HTTPDaemon implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            String method = t.getRequestMethod();
            String response;
            int code;
            String URL = null;
            boolean shouldSolicit = false;
            if (Objects.equals(method, "POST")) {
                System.out.println("POST received");
                Headers header = t.getRequestHeaders();
                String body = getBody(t);
                String mainHeader = null;
                String type = null;

                code = 500;
                response = "%MISUNDERSTOOD";

                if (header.containsKey("request")){
                    mainHeader = "request";
                    type = header.get("request").get(0);
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
                                    resultSet = Operations.executeQuery("SELECT UUID, NAME, AUTHENTICATOR, LAST_STATUS FROM CAMERAS WHERE OWNER='" + user.getUserID() + "'");
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
                            String address = t.getRemoteAddress().toString();
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

                                System.out.println("Updated base " + serial + " with status " + status + " and IP " + t.getRemoteAddress());
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
                                    response = Operations.findSpecificResult(set, "LAST_IP").split("/")[1];
                                    System.out.println(response + ": Last IP");
                                    code = 200;
                                }
                            } catch (SQLException e) {
                                e.printStackTrace();
                            }

                        }
                        case "weather" -> {
                            /*
                            The format for requesting weather data consists of the following:
                            Serial = the serial of the camera, also known as the UUID
                            Authenticator = the known password of the base
                            Session ID = The User's session ID
                            User ID = The user's ID

                            within this format, we can ask for the weather status, if there is one:
                            HEADER REQUEST WEATHER
                            BODY "<serial>|<authenticator>|<user_id>|<session_id>
                            if authenticated, therefore relay last weather, else relay command %NULL
                             */

                            String[] splitBody = body.split("\\|");
                            String serial = splitBody[0];
                            String authenticator = splitBody[1];
                            String userID = splitBody[2];
                            String sessionKey = splitBody[3];


                            UserAuth user = new UserAuth(Integer.parseInt(userID), sessionKey);
                            if (!user.validate()) {
                                response = "%INVALID_USER";
                                code = 401;
                                break;
                            }
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
                                    response = "%INVALID_BASE";
                                    System.err.println("Auth failure, " + remoteAuth + " vs " + authenticator);
                                    break;
                                }
                            } catch (SQLException e) {
                                e.printStackTrace();
                            }
                            if (Server.weatherData.containsKey(serial)){
                                response = Server.weatherData.get(serial);
                                code = 200;
                            } else {
                                response = "%NO_DATA";
                                code = 204;
                            }


                        }
                    }
                } else

                if (header.containsKey("solicit")){
                    mainHeader = "solicit";
                    type = header.get("solicit").get(0);
                    switch (type) {
                        case "connection" -> {
                            String[] address = t.getRemoteAddress().toString().split("[/:]");
                            System.out.println(Arrays.toString(address));

                            System.out.println("Solicitation requested at ip " + address[1] + " and port " + body);
                            try {
                                URL = "https://" + address[1] + ":" + body + "/test";
                                System.out.println("Contacting " + URL + "...");
                                shouldSolicit = true;
                                response = "%SUCCESS";
                                code = 210;
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                        case "weather" -> {
                            //pick apart the request

                            String[] split1 = body.split("\n");

                            String[] authSplit = split1[0].split("\\|");

                            String serial = authSplit[0];
                            String authenticator = authSplit[1];
                            String weatherdata = split1[1];

                            try {
                                ResultSet set = Operations.executeQuery("SELECT AUTHENTICATOR FROM CAMERAS WHERE UUID='" + serial + "'");

                                if (set == null) {
                                    code = 404;
                                    response = "%NOT_FOUND";
                                    System.err.println("Base not found: " + serial);
                                    break;
                                }
                                String remoteAuth = Operations.findSpecificResult(set, "AUTHENTICATOR");

                                if (!remoteAuth.equals(authenticator)) {
                                    code = 401;
                                    response = "%INVALID";
                                    System.err.println("Auth failure, " + remoteAuth + " vs " + authenticator);
                                    break;
                                }
                                Server.weatherData.put(serial, weatherdata);
                                code = 201;
                                response = "%UPDATED";
                            } catch (SQLException e) {
                                e.printStackTrace();
                            }

                        }
                        case "speaker" -> {
                            /*
                            The format in which a user can play a sound requires that
                            they verify they are a valid user. The format in which data should come in
                            looks like:
                            HEADER SOLICIT SPEAKER
                            BODY "<serial>|<authenticator>|<user_id>|<session_id>

                             */
                            String[] splitBody = body.split("\\|");
                            String serial = splitBody[0];
                            String authenticator = splitBody[1];
                            String userID = splitBody[2];
                            String sessionKey = splitBody[3];

                            System.out.println("Solicit speaker requested, data here: "+serial + "|" + authenticator + "|" + userID + "|" + sessionKey);

                            UserAuth user = new UserAuth(Integer.parseInt(userID), sessionKey);
                            if (!user.validate()) {
                                response = "%INVALID_USER";
                                code = 401;
                                break;
                            }
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
                                    response = "%INVALID_BASE";
                                    System.err.println("Auth failure, " + remoteAuth + " vs " + authenticator);
                                    break;
                                }
                            } catch (SQLException e) {
                                e.printStackTrace();
                            }

                            //They have identified themselves, and they also identified the camera. Now send the speaker packet
                            /*
                            some notes
                            I have recently discovered a thing called MQTT, or Message Queuing Telemetry Transport. This system
                            is interesting because both users and devices can 'subscribe' to a certain datatype, which makes it
                            easy to send and recieve data from client to device and vice versa.
                             */

                            try {
                                Main.client.publish(serial + "-A", new MqttMessage());
                                response = "%ACCEPTED";
                                code = 200;
                                System.out.println("Speaker request accepted");
                            } catch (MqttException e) {
                                e.printStackTrace();
                            }

                        }
                    }
                } else {
                    response = "%NO_HEADER";
                    code = 200;
                }

                System.out.println(body + "\nHEADER: " + mainHeader + ", KEY: " + type);
                assert response != null;
                respond(t, code, response);
                if (shouldSolicit) {
                    try {
                        Https.Request request = Https.get(URL, new HashMap<>());
                        System.out.println(request.getBody() + ", " + request.getStatus());
                    } catch (NoSuchAlgorithmException | KeyManagementException e) {
                        e.printStackTrace();
                    }
                }

            }
            if (Objects.equals(method, "GET")){
                System.out.println("GET Received");
                List<String> header = new ArrayList<>();
                if (t.getRequestHeaders().containsKey("request")) header = t.getRequestHeaders().get("request");
                code = 500;
                if (!header.isEmpty()){
                    if (header.get(0).equals("source")){
                        code = 200;
                        response = t.getRemoteAddress().toString().split(":")[1];
                    }
                    else {
                        response = "%MISUNDERSTOOD";
                    }
                    System.out.println("GET received: " + response);
                } else{
                    response = "%NO_HEADER";
                    code = 200;
                }
                respond(t, code, response);
            }

            //Form the string to be sent
        }
    }
}
