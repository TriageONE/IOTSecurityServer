package com.security.server.auth;

import com.security.server.http.Server;

import javax.swing.plaf.PanelUI;
import java.util.UUID;

public class UserAuth {

    private int userID;
    private UUID sessionKey;

    public UserAuth(int id, UUID uuid){
        this.userID = id;
        this.sessionKey = uuid;
    }
    public UserAuth(int id, String uuid){
        this.userID = id;
        this.sessionKey = UUID.fromString(uuid);
    }


    public boolean validate(){
        //Does the session list contain the key?
        System.out.println("Detecting if key exists");
        if (Server.sids.containsKey(this.sessionKey)){
            System.out.println("Key detected: " + this.sessionKey);

            //If it does, check if the user id presented is the same as the one in the session identifier
            return Server.sids.get(this.sessionKey) == this.userID;
        }
        System.out.println("Key not found: " + this.sessionKey);
        return false;
    }

    public int getUserID() {
        return userID;
    }

    public void setUserID(int userID) {
        this.userID = userID;
    }

    public UUID getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(UUID sessionKey) {
        this.sessionKey = sessionKey;
    }
}
