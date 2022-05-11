package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public class Server extends EncryptedChat{
    private static Message msg;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        DatagramSocket serverSocket = new DatagramSocket(25565);
        KeyPair kp = genKeyPair(2048);
        byte[] in = new byte[2048];
        DatagramPacket recive = new DatagramPacket(in, in.length);
        serverSocket.receive(recive);
        PublicKey recvPublicKey = getPublicKey(recive.getData());
        DatagramPacket send = new DatagramPacket(kp.getPublic().getEncoded(), kp.getPublic().getEncoded().length, recive.getAddress(), recive.getPort());
        serverSocket.send(send);
        while(true){
            byte[] toDecryptBytes = new byte[256];
            DatagramPacket toDecrypt = new DatagramPacket(toDecryptBytes, toDecryptBytes.length);
            serverSocket.receive(toDecrypt);
            byte[] decryptedBytes = getDecryptedMsg(kp.getPrivate(), toDecrypt.getData());
            String toRead = new String(decryptedBytes);
            System.out.println(toRead);
            if(toRead.equals("!quit")){
                byte[] toSend = getCryptedMsg(recvPublicKey,"<close>".getBytes());
                DatagramPacket packageToSend = new DatagramPacket(toSend, toSend.length, toDecrypt.getAddress(), toDecrypt.getPort());
                serverSocket.send(packageToSend);
            }
            else{
                byte[] toSend = getCryptedMsg(recvPublicKey,"<ok>".getBytes());
                DatagramPacket packageToSend = new DatagramPacket(toSend, toSend.length, toDecrypt.getAddress(), toDecrypt.getPort());
                serverSocket.send(packageToSend);
            }
        }
    }
}
