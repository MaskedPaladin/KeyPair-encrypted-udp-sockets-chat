package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Scanner;

public class EncryptedChat {
    protected static KeyPair genKeyPair(int size) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }

    protected static byte[] getCryptedMsg(PublicKey puk, byte[] msg) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, puk);
        return c.doFinal(msg);
    }
    protected static byte[] getDecryptedMsg(PrivateKey prk, byte[] msg) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, prk);
        return c.doFinal(msg);
    }
    protected static PublicKey getPublicKey(byte[] puk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKey = new X509EncodedKeySpec(puk);
        return kf.generatePublic(publicKey);
    }
    protected static void runServer() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        MulticastSocket serverSocket = new MulticastSocket(25565);
        KeyPair kp = genKeyPair(2048);
        byte[] in = new byte[2048];
        DatagramPacket recive = new DatagramPacket(in, in.length);
        serverSocket.receive(recive);
        PublicKey recvPublicKey = getPublicKey(recive.getData());
        DatagramPacket send = new DatagramPacket(kp.getPublic().getEncoded(), kp.getPublic().getEncoded().length, recive.getAddress(), recive.getPort());
        serverSocket.send(send);
        while(true){
            ArrayList<KeyPair> keyPairs = new ArrayList<KeyPair>();
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
    protected static void runClient() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        MulticastSocket clientSocket = new MulticastSocket();
        KeyPair kp = genKeyPair(2048);
        DatagramPacket send = new DatagramPacket(kp.getPublic().getEncoded(), kp.getPublic().getEncoded().length, InetAddress.getLocalHost() ,25565);
        clientSocket.send(send);
        byte[] in = new byte[2048];
        DatagramPacket recive = new DatagramPacket(in, in.length);
        clientSocket.receive(recive);
        PublicKey recvPublicKey = getPublicKey(recive.getData());
        while(true){
            Scanner sc = new Scanner(System.in);
            String toEncrypt = sc.next();
            byte[] toSend = getCryptedMsg(recvPublicKey, toEncrypt.getBytes());
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

