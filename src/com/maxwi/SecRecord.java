package com.maxwi;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SecRecord {

    public static void main(String[] args) {
        // write your code here
        String srcPath = "滕王阁序英文版.doc";
        String enPath = "滕王阁序英文版.doc.aes";
        String dePath = "滕王阁序英文版_dec.doc";
//        Scanner in = new Scanner(System.in);
//        System.out.println("Enter Password:");
        String passWord = "blueyiniu";
        if (passWord.isEmpty()) {
            System.out.println("Password Error!");
        }
        if (CryptFile.enCryptFile(enPath, srcPath, passWord)) {
            System.out.println("Encrypt Success!");
        }
        else {
            System.out.println("Encrypt Failed!");
        }

        if (CryptFile.deCryptFile(dePath, enPath, passWord)) {
            System.out.println("Decrypt Success!");
        }
        else {
            System.out.println("Decrypt Failed!");
        }
    }
}

class CryptFile {

    private static final int BUFFER_SIZE = 4096;
    public static boolean enCryptFile(String dstPath, String srcPath, String passWord) {
        return cryptFile(dstPath, srcPath, passWord, true);
    }

    public static boolean deCryptFile(String dstPath, String srcPath, String passWord) {
        return cryptFile(dstPath, srcPath, passWord, false);
    }

    private static boolean cryptFile(String dstPath, String srcPath, String passWord, boolean bIsEnCrypt) {
        File inFile = new File(srcPath);
        InputStream inS;
        OutputStream outS;
        if (!inFile.exists()) {
            System.out.println("File: " + srcPath + " Not Exist!");
            return false;
        }
        try {
            inS = new FileInputStream(inFile);
            outS = new FileOutputStream(dstPath);

            byte[] byteSrcBuffer;
            byte[] byteDstBuffer;
            int readLen;

            if (bIsEnCrypt) {
                byteSrcBuffer = new byte[BUFFER_SIZE];
                while (-1 != (readLen = inS.read(byteSrcBuffer))) {
                    if (BUFFER_SIZE != readLen) {
                        byteSrcBuffer = Arrays.copyOf(byteSrcBuffer, readLen);
                    }
                    byteDstBuffer = AESUtil.encrypt(byteSrcBuffer, passWord);

                    if (null == byteDstBuffer) {
                        inS.close();
                        outS.close();
                        return false;
                    }
                    byte[] cryLen = intToByteArray(byteDstBuffer.length);
                    outS.write(cryLen);
                    outS.write(byteDstBuffer);
                }
            }
            else {
                byte[] cryptLen = new byte[4];
                if (4 != inS.read(cryptLen)) {
                    return false;
                }
                readLen = byteArrayToInt(cryptLen);
                byteSrcBuffer = new byte[readLen];
                int realReadLen;
                while (-1 != (realReadLen = inS.read(byteSrcBuffer))) {
                    if (readLen != realReadLen) {
                        return false;
                    }

                    byteDstBuffer = AESUtil.decrypt(byteSrcBuffer, passWord);

                    if (null == byteDstBuffer) {
                        inS.close();
                        outS.close();
                        return false;
                    }

                    outS.write(byteDstBuffer);

                    if (0 == inS.read(cryptLen)) {
                        return true;
                    }

                    readLen = byteArrayToInt(cryptLen);
                    byteSrcBuffer = new byte[readLen];
                }
            }
            inS.close();
            outS.close();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * int到byte[]
     */
    private static byte[] intToByteArray(int i) {
        byte[] result = new byte[4];
        //由高位到低位
        result[0] = (byte)((i >> 24) & 0xFF);
        result[1] = (byte)((i >> 16) & 0xFF);
        result[2] = (byte)((i >> 8) & 0xFF);
        result[3] = (byte)(i & 0xFF);
        return result;
    }

    /**
     * byte[]转int
     */
    private static int byteArrayToInt(byte[] bytes) {
        int value=0;
        //由高位到低位
        for(int i = 0; i < 4; i++) {
            int shift= (4-1-i) * 8;
            value +=(bytes[i] & 0x000000FF) << shift;//往高位游
        }
        return value;
    }

}

/**
 * @version V1.0
 * @desc AES 加密工具类
 */
class AESUtil {

    private static final String KEY_ALGORITHM = "AES";
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";//默认的加密算法

    public static byte[] encrypt(byte[] byteSrc, String password) {
        try {
            Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(password));
            return cipher.doFinal(byteSrc);
        }
        catch (Exception ex) {
            Logger.getLogger(AESUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * AES 加密操作
     *
     * @param content  待加密内容
     * @param password 加密密码
     * @return 返回Base64转码后的加密数据
     */
    public static String encrypt(String content, String password) {
        try {
            byte[] byteContent = content.getBytes("utf-8");
            byte[] result = encrypt(byteContent, password);
            if (null != result) {
                return Base64.getEncoder().encodeToString(result);
            }
            else {
                return null;
            }
        }
        catch (Exception ex) {
            Logger.getLogger(AESUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static byte[] decrypt(byte[] byteSrc, String password) {
        try {
            //实例化
            Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
            //使用密钥初始化，设置为解密模式
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(password));
            //执行操作
            return cipher.doFinal(byteSrc);
        } catch (Exception ex) {
            Logger.getLogger(AESUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }


    /**
     * AES 解密操作
     */
    public static String decrypt(String content, String password) {
        try {
            byte[] result = decrypt(Base64.getDecoder().decode(content), password);
            if (null != result) {
                return new String(result, "utf-8");
            }
            else {
                return null;
            }
        }
        catch (Exception ex) {
            Logger.getLogger(AESUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * 生成加密秘钥
     */
    private static SecretKeySpec getSecretKey(final String password) {
        //返回生成指定算法密钥生成器的 KeyGenerator 对象
        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance(KEY_ALGORITHM);
            //AES 要求密钥长度为 128
            kg.init(128, new SecureRandom(password.getBytes()));
            //生成一个密钥
            SecretKey secretKey = kg.generateKey();
            return new SecretKeySpec(secretKey.getEncoded(), KEY_ALGORITHM);// 转换为AES专用密钥
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AESUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
