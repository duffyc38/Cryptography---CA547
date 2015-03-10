import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;

//Program attempts to encrypt a file using RSA
class Assignment2
{
	//Generates the random BigInteger values p and q
	private static BigInteger createRandomPrime()
	{
		//SecureRandom makes value harder to predict
		SecureRandom rnd = new SecureRandom();
		//Generate a probably prime number of 512 bits
		BigInteger probablePrime = BigInteger.probablePrime(512, rnd);
		return probablePrime;
	}
	
	//Gets the product N
	private static BigInteger getProduct(BigInteger p, BigInteger q)
	{
		return p.multiply(q);
	}
	
	//Calculates the phi(N)
	private static BigInteger getPhi(BigInteger p, BigInteger q)
	{
		BigInteger one = BigInteger.ONE;
		//Calculates using formula: phi(N) = (p-1)(q-1)
		return (p.subtract(one)).multiply(q.subtract(one));
	}
	
	//Ensures that e(65537) is relatively prime to phi(N)
	private static BigInteger getGCD(BigInteger N, BigInteger e)
	{
		//Implements the Euclidean algorithm
		if(e.compareTo(BigInteger.ZERO) == 0)
		{
			return N;
		}
		BigInteger temp = N.mod(e);
		//Recursive method continues until value e reduced to 0
		return getGCD(e, temp);
	}
	
	//Calculates the inverse
	//Based on method found here: http://www-math.ucdenver.edu/~wcherowi/courses/m5410/exeucalg.html
	private static BigInteger inverse(BigInteger a, BigInteger b)
	{
		BigInteger x = BigInteger.ZERO;
		BigInteger x1 = BigInteger.ONE;
		
		BigInteger temp = BigInteger.ZERO;
		
		BigInteger originalMod = a;
		
		while(b.compareTo(BigInteger.ZERO) != 0)
		{
			BigInteger numDivisions = a.divide(b);
			BigInteger remainder = a.mod(b);
			
			a = b;
			b = remainder;
			
			temp = x1;
			x1 = (x.subtract(x1.multiply(numDivisions))).mod(originalMod);
			x = temp;
			
		}
		return x;
	}
	
	//Generates the 256-but hash used in the RSA encryption
	private static byte [] getDigest(byte [] input) throws NoSuchAlgorithmException
	{
		//Set to Sha-256
		MessageDigest message = MessageDigest.getInstance("SHA-256");
		message.update(input);
		//Generate the digest and place in a byte array
		byte [] zipDigest = message.digest();
		
		return zipDigest;
	}
	
	//Prints out the required values in hexadecimal
	private static void printValuesToFile(BigInteger N)
	{
		try
		{
			//Create the file which will hold the encrypted information 
			PrintWriter printValues = new PrintWriter("Values.txt");
			//Place encrypted information in the file
			printValues.write("Value of N: " + N.toString(16));
		
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
			//Set the values for both N and e(65537)
			BigInteger encryptEx = new BigInteger("65537");
			BigInteger product = BigInteger.ZERO;
			BigInteger phi = BigInteger.ZERO;
			BigInteger result = BigInteger.ZERO;
			while(result.compareTo(BigInteger.ONE) != 0)
			{
				//Generate the two probable primes
				BigInteger p = createRandomPrime();
				BigInteger q = createRandomPrime();
				//Get the product N
				product = getProduct(p, q);
				//Calculate the phi(N)
				phi = getPhi(p, q);
				//Preformed to see if e and N are relatively prime
				result = getGCD(phi, encryptEx);
			}
			System.out.println(product);
			//Get the inverse d
			BigInteger inverse = inverse(phi, encryptEx);
			
			//Read in the input file to be encrypted.
			File input = new File("Assignment2.zip");
			FileInputStream inputStream = new FileInputStream(input);
			byte[] inputBytes = new byte[(int) input.length()];
			inputStream.read(inputBytes);
			//Produce the digest using SHA-256
			byte [] digest = getDigest(inputBytes);
			BigInteger message = new BigInteger(digest);
			
			/*
				NOTE: Final steps would have included:
					- Calculating c^d mod N
					- Output the values for N and the file in hexadecimal
			*/
			inputStream.close();
			//Print values, would have been used to print hexadecimal value of digest
			printValuesToFile(product);
		}
		catch(IOException e)
		{
			System.out.println("IO Operation failed");
		}
		catch(NoSuchAlgorithmException e)
		{
			System.out.println("Algorithm Failed");
		}
		
	}
}
