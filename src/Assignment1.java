// 2020/2021 CA4005 Cryptography and Security Protocols
// Assignment 1: Symmetric Encryption Using Diffie-Hellman Key Agreement
// By Connell Kelly

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import static java.util.Collections.singletonList;
import java.util.List;

public class Assignment1
{

    private static BigInteger dhMod(BigInteger a, BigInteger expo, BigInteger mod)
    {
        // Determine bitlength
        int bitLen = expo.bitLength();
        BigInteger b = new BigInteger("1");

        // Calculate Diffie-Hellman Key Exchange
        for (int i = bitLen - 1; i >= 0; i--)
        {
            b = b.multiply(b).mod(mod);
            if (expo.testBit(i))
            {
                b = b.multiply(a).mod(mod);
            }
        }
        return b;
    }

    private static SecretKeySpec genAES(BigInteger s) throws NoSuchAlgorithmException
    {
        // Produce 256-bit digest
        MessageDigest messageD = MessageDigest.getInstance("SHA-256");
        // Determine 256-bit AES Key 'k'
        byte[] k = messageD.digest(s.toByteArray());
        return new SecretKeySpec(k, "AES");
    }

    private static IvParameterSpec genIV()
    {
        // Define Initialisation Vector of 16 bytes (128 bits)
        byte[] iVector = new byte[16];

        // Use SecureRandom() to determine an array of random numbers
        SecureRandom rando = new SecureRandom();
        rando.nextBytes(iVector);

        // Return IV object
        return new IvParameterSpec(iVector);
    }

    private static void padInput(byte[] a, int len, int padLen)
    {
        // 128 byte padding
        a[len] = (byte) 128;

        // Formula for padding
        for (int i = 1; i < padLen; i++)
        {
            a[len + 1] = (byte) 0;
        }
    }

    private static void writeValue(String path, String strOutput) throws IOException
    {
        // Writing Diffie-Hellman Key Exchange calculation and Initialisation Vector to an indicated file
        Charset utf8 = StandardCharsets.UTF_8;
        List<String> outputList = singletonList(strOutput);
        Files.write(Paths.get(path), outputList, utf8);
    }

    public static void main(String[] args)
    {

        // Hexidecimal codes that will be converted to decimals.
        // BigInteger will manage the extremely large resulting decimals.
        // Prime Modulus 'p'
        BigInteger p = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
        // Generator 'g'
        BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);
        // Public Shared Key 'A'
        BigInteger A = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d", 16);

        // SecureRandom() will help generate a random 1023-bit integer.
        // Personal Private Key 'b'
        BigInteger b = new BigInteger(1023, new SecureRandom());

        // Diffie-Hellman key exchange will be performed with dhMod().
        // Personal Public Key 'B'
        BigInteger B = dhMod(g, b, p);
        // Shared Secret Key 's'
        BigInteger s = dhMod(A, b, p);

        try
        {
            // Inputted file to be encrypted
            File inpFile = new File(args[0]);
            FileInputStream fileInpStream = new FileInputStream(inpFile);
            int fileLen = (int) inpFile.length();
            int padLen = 16 - (fileLen % 16);
            byte[] inp = new byte[fileLen + padLen];

            // Close off input stream
            fileInpStream.close();

            // Pad out input
            padInput(inp, fileLen, padLen);

            // Initialisation Vector (IV) generation
            IvParameterSpec iv = genIV();

            // AES Key 'k' generated from Shared Key 's'
            SecretKeySpec k = genAES(s);

            // Cipher initialisation
            Cipher ciph = Cipher.getInstance("AES/CBC/NoPadding");
            ciph.init(Cipher.ENCRYPT_MODE, k, iv);

            // Byte array encryption
            byte[] byteOutput = ciph.doFinal(inp);
            String strCipher = "";
            for(Byte encByte: byteOutput)
            {
                Integer encInt = Byte.toUnsignedInt(encByte);
                strCipher = strCipher + Integer.toHexString(encInt);
            }
            System.out.print(strCipher);

            String strIV = "";
            for (byte by : iv.getIV())
            {
                String strHex = String.format("%02X", by);
                strIV = strIV + strHex;
            }

            // Convert Personal Public Key to hexidecimal format and write to DH.txt
            writeValue("DH.txt", B.toString(16));

            // Write Initialisation Vector to IV.txt
            writeValue("IV.txt", strIV);

        } catch
        (IOException
                        | NoSuchAlgorithmException
                        | NoSuchPaddingException
                        | BadPaddingException
                        | InvalidAlgorithmParameterException
                        | InvalidKeyException
                        | IllegalBlockSizeException e)
        {
            System.out.println(e);
        }
    }
}
