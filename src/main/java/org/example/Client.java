package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class Client extends EncryptedChat{
    private static Message msg;
    static Scanner sc = new Scanner(System.in);
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        DatagramSocket clientSocket = new DatagramSocket();
        KeyPair kp = genKeyPair(2048);
        DatagramPacket send = new DatagramPacket(kp.getPublic().getEncoded(), kp.getPublic().getEncoded().length, InetAddress.getLocalHost() ,25565);
        clientSocket.send(send);
        byte[] in = new byte[2048];
        DatagramPacket recive = new DatagramPacket(in, in.length);
        clientSocket.receive(recive);
        PublicKey recvPublicKey = getPublicKey(recive.getData());
        while(true){
            String toEncrypt = sc.next();
            byte[] toSend = getCryptedMsg(recvPublicKey, toEncrypt.getBytes());
            DatagramPacket packageToSend = new DatagramPacket(toSend, toSend.length, InetAddress.getLocalHost() ,25565);
            clientSocket.send(packageToSend);
            byte[] toDecryptBytes = new byte[256];
            DatagramPacket toDecrypt = new DatagramPacket(toDecryptBytes, toDecryptBytes.length);
            clientSocket.receive(toDecrypt);
            byte[] decryptedMsg = getDecryptedMsg(kp.getPrivate(), toDecrypt.getData());
            String toRead = new String(decryptedMsg);
            System.out.println(toRead);
            byte[] confToRecv = new byte[256];
            DatagramPacket confirmationToRecv = new DatagramPacket(confToRecv, confToRecv.length);
            clientSocket.receive(confirmationToRecv);
            byte[] decryptedConfirmation = getDecryptedMsg(kp.getPrivate(), confirmationToRecv.getData());
            String confirmation = new String(decryptedConfirmation);
            System.out.println(confirmation);
            if(confirmation.equals("<close>")){
                clientSocket.close();
                break;
            }
        }
    }
}

