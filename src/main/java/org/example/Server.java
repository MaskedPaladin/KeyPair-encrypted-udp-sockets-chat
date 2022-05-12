package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

public class Server extends EncryptedChat{
    private static Message msg;
    private static ArrayList<PublicKey> pKeys = new ArrayList<PublicKey>();

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        MulticastSocket serverSocket = new MulticastSocket(25565);
        KeyPair kp = genKeyPair(2048);
        while(true){
            byte[] in = new byte[2048];
            DatagramPacket recive = new DatagramPacket(in, in.length);
            serverSocket.receive(recive);
            if(recive.getLength() > 256 ){
                PublicKey recvPublicKey = getPublicKey(recive.getData());
                System.out.println(recvPublicKey);
                pKeys.add(recvPublicKey);
                DatagramPacket send = new DatagramPacket(kp.getPublic().getEncoded(), kp.getPublic().getEncoded().length, recive.getAddress(), recive.getPort());
                serverSocket.send(send);
            }
            else{
                for (PublicKey p : pKeys){
                    System.out.println(p);
                    byte[] toDecryptBytes = new byte[256];
                    DatagramPacket toDecrypt = new DatagramPacket(toDecryptBytes, toDecryptBytes.length);
                    serverSocket.receive(toDecrypt);
                    byte[] decryptedBytes = getDecryptedMsg(kp.getPrivate(), toDecrypt.getData());
                    String toRead = new String(decryptedBytes);
                    System.out.println(toRead);
                    if(toRead.equals("!quit")){
                        byte[] toSend = getCryptedMsg(p,"<close>".getBytes());
                        DatagramPacket packageToSend = new DatagramPacket(toSend, toSend.length, toDecrypt.getAddress(), toDecrypt.getPort());
                        serverSocket.send(packageToSend);
                    }
                    else{
                        byte[] toSend = getCryptedMsg(p,"<ok>".getBytes());
                        DatagramPacket packageToSend = new DatagramPacket(toSend, toSend.length, toDecrypt.getAddress(), toDecrypt.getPort());
                        serverSocket.send(packageToSend);
                    }
                }
            }
        }

    }
    public static ArrayList<PublicKey> removeDuplicates(ArrayList<PublicKey> ips){
        ArrayList<PublicKey> newPK = new ArrayList<PublicKey>();
        for(PublicKey i : newPK){
            if (!ips.contains(i)) {
                newPK.add(i);
            }
        }
        return newPK;
    }
}
