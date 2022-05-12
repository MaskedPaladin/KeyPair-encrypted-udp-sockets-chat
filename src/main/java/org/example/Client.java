package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Scanner;

public class Client extends EncryptedChat{
    private static Message msg;
    static Scanner sc = new Scanner(System.in);
    private static ArrayList<PublicKey> pKeys = new ArrayList<PublicKey>();
    private static boolean sended = false;
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        MulticastSocket clientSocket = new MulticastSocket();
        KeyPair kp = genKeyPair(2048);

        while(true){
            if(!sended){
                DatagramPacket send = new DatagramPacket(kp.getPublic().getEncoded(), kp.getPublic().getEncoded().length, InetAddress.getLocalHost() ,25565);
                clientSocket.send(send);
            }

            byte[] in = new byte[2048];
            DatagramPacket recive = new DatagramPacket(in, in.length);
            clientSocket.receive(recive);
            if(recive.getLength() > 256){
                PublicKey recvPublicKey = getPublicKey(recive.getData());
                System.out.println(recvPublicKey);
                pKeys.add(recvPublicKey);
                sended = true;
            }
            else{
                Scanner sc = new Scanner(System.in);
                String toEncrypt = sc.next();
                for(PublicKey p : pKeys){
                    System.out.println(p);
                    byte[] toSend = getCryptedMsg(p, toEncrypt.getBytes());
                    DatagramPacket packageToSend = new DatagramPacket(toSend, toSend.length, InetAddress.getLocalHost() ,25565);
                    clientSocket.send(packageToSend);
                    byte[] toDecryptBytes = new byte[256];
                    DatagramPacket toDecrypt = new DatagramPacket(toDecryptBytes, toDecryptBytes.length);
                    clientSocket.receive(toDecrypt);
                    byte[] decryptedMsg = getDecryptedMsg(kp.getPrivate(), toDecrypt.getData());
                    String toRead = new String(decryptedMsg);
                    if(toRead.equals("<close>")){
                        clientSocket.close();
                        break;
                    }
                    System.out.println(toRead);
                }
            }

        }
    }
}

