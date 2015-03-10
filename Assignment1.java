import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;


class Assignment1
{
	//Generates a random value which will be used to produce a Key
	public static BigInteger generateRandomKey()
	{
		//Using SecureRandom as it is more difficult to predict value
		SecureRandom rnd = new SecureRandom();
		BigInteger randomPKey = new BigInteger(1023, rnd);
		return randomPKey;
	}
	
	//Used the "Square and Multiply" algorithm to generate the result
	//Used page 9 and 10 of Number Theory notes 
	//Also used the following as a reference: http://stackoverflow.com/questions/101439/the-most-efficient-way-to-implement-an-integer-based-power-function-powint-int
	private static BigInteger modExp(BigInteger orgValue, BigInteger power, BigInteger modulus)
	{
		BigInteger result = BigInteger.ONE;
		while(power.compareTo(BigInteger.ZERO) > 0)
		{
			if(power.testBit(0))
			{
				result = (result.multiply(orgValue)).mod(modulus);
			}
			power = power.shiftRight(1);
			orgValue = (orgValue.multiply(orgValue)).mod(modulus);
		}
		return result;
	}
	
	//Pads the message before encryption as per the assignment's specifications
	private static byte [] customPadding(byte [] plaintext, int blocksize)
	{
		//Evaluate what padding needs to be applied 
		int difference = plaintext.length % blocksize;
		int paddingSize = blocksize - difference;
		//Create a new byte array to be used as padding
		byte [] padding = new byte[paddingSize];
		//Insert required values into byte array
		if(difference > 0)
		{
			padding[0] = (byte)-128;
			for(int i = 1; i < paddingSize -1; i++)
			{
				padding[i] = (byte)0;
			}
		}
		else
		{
			padding[0] = (byte)-128;
			for(int i = 1; i < paddingSize; i++)
			{
				padding[i] = (byte)0;
			}
		}
		//Create a new array which will take the contents of both arrays above
		byte[] postPadding = new byte[plaintext.length + padding.length]; 
		//Copies the contents of each array into the final result
		System.arraycopy(plaintext, 0, postPadding, 0, plaintext.length); 
		System.arraycopy(padding, 0, postPadding, plaintext.length, padding.length);
		
		return postPadding;
	}
	
	//Generates the digest which produces the 256 bit key used for the AES encryption
	private static byte [] getDigest(BigInteger sharedKey) throws NoSuchAlgorithmException
	{
		byte [] sharedKeyArray = sharedKey.toByteArray();
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(sharedKeyArray);
		byte [] sharedKeyDigest = md.digest();
		
		return sharedKeyDigest;
	}
	
	//Creates a randomly generated 128-bit Iv used for the AES encryption
	private static byte [] generateRandomIV()
	{
		//Create random bytes for the IV
		byte [] iv = new byte[16];
		SecureRandom rnd = new SecureRandom();
		rnd.nextBytes(iv);
		//Print to record value
		BigInteger ivValue = new BigInteger(iv);

		return iv;
	}
	
	//Prints out the required values in hexadecimal
	private static void printValuesToFile(BigInteger keyB, BigInteger iv, BigInteger output)
	{
		try
		{
			//Create the file which will hold the encrypted information 
			PrintWriter printValues = new PrintWriter("RequiredValues.txt");
			//Place encrypted information in the file
			printValues.write("Public Key B Value: " + keyB.toString(16));
			printValues.println();
			printValues.write("Iv Value: " + iv.toString(16));
			printValues.println();
			printValues.write("AES Encryption Value: " + output.toString(16));
			printValues.close();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("Error writing to file");
		}
	}
	
	public static void main(String [] args) 
	{
		try
		{
			//Temporarily store hexadecimal values for future BigIntegers objects
			String primeString = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6edd" +
								 "ef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc" +
								 "8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f" +
								 "47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
			
			String genString = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2" +
							   "e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e8864" +
							   "1a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f5496" +
							   "64bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
												
			String pubKeyString = "5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1" +
								  "b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111" +
								  "d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15" +
								  "171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d";
			
			//Create three BigInteger objects to hold supplied hexadecimal values
			BigInteger primeMod = new BigInteger(primeString, 16);
			BigInteger generator = new BigInteger(genString, 16);		
			BigInteger publicKeyA = new BigInteger(pubKeyString, 16);

			//Generate the value that will be used to create private Key
			BigInteger pKey = generateRandomKey();
			System.out.println(pKey.bitLength());
			
			//Generate the public key B using the modular exponentiation
			BigInteger publicKeyB = modExp(generator, pKey, primeMod);
			
			//Use the values generated and supplied to create shared key
			BigInteger sharedKey = modExp(publicKeyB, pKey, primeMod);
			System.out.println(sharedKey.bitLength());
			
			//Generate the digest to get the required 256-bit AES key
			byte [] sharedKeyDigest = getDigest(sharedKey);
			
			//Read in the file to be encrypted
			File inputFile = new File("Assignment1.zip");
			FileInputStream inputStream = new FileInputStream(inputFile);
			byte[] inputBytes = new byte[(int) inputFile.length()];
			inputStream.read(inputBytes);
			
			//Apply padding to the file 
			inputBytes = customPadding(inputBytes, 16);
			
			//Create the key object to be used in the encryption
			SecretKeySpec secretKey = new SecretKeySpec(sharedKeyDigest, "AES");
			
			//Get the random IV to be used in the encryption process
			byte [] iv = generateRandomIV();
			BigInteger printIV = new BigInteger(iv);
			
			//Create cipher which will hold the above info and perform encryption
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
			
			//Output the encrypted file information into a byte array
			byte [] output = cipher.doFinal(inputBytes);
			BigInteger outputHex = new BigInteger(output);
			
			//Create the file which will hold the encrypted information 
			FileOutputStream outputStream = new FileOutputStream("EncryptedAssignment1.zip");
			//Place encrypted information in the file
			outputStream.write(output);
				 
			inputStream.close();
			outputStream.close();
			//Print the required values in hexadecimal
			printValuesToFile(publicKeyB, printIV, outputHex);
		} 
		catch(NoSuchAlgorithmException e)
		{
			System.out.println("Error with algorithm");
		}
		catch(IOException io)
		{
			System.out.println("Error reading/writing to file");
		}
		catch(NoSuchPaddingException pad)
		{
			System.out.println("Error padding file");
		}
		catch(IllegalBlockSizeException block)
		{
			System.out.println("Error with block size");
		}
		catch(InvalidKeyException key)
		{
			System.out.println("Error with key");
		}
		catch(InvalidAlgorithmParameterException e)
		{
			System.out.println("Error woth algorothm parameter");
		}
		catch(BadPaddingException badPad)
		{
			System.out.println("Error with padding");
		}
	}
}
