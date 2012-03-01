package com.bluemeanie.kapital.shared.core;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

public class TripleContract extends Message
 implements Serializable {

	byte[] signatureRecipient;
	byte[] signatureNotary;
	
	TripleContract(){};
	
	TripleContract( String payload ){
		super(payload);
	}
	
	TripleContract( String payload, PrivateKey signer ){};
	
	byte[] signRecipient( PrivateKey privateKey , Signature sig ) throws InvalidKeyException, SignatureException{
		sig.initSign( privateKey );
	    sig.update( payload );
	    this.signatureRecipient = sig.sign();
	    return this.signatureRecipient;
	}
	
	public boolean verifyRecipient( PublicKey publicKey, Signature sig ) throws InvalidKeyException, SignatureException{
		sig.initVerify( publicKey );
		sig.update( this.payload );
		return sig.verify( this.signatureRecipient );
	}
	
	byte[] signNotary( PrivateKey privateKey , Signature sig ) throws InvalidKeyException, SignatureException{
		sig.initSign( privateKey );
	    sig.update( payload );
	    this.signatureNotary = sig.sign();
	    return this.signatureNotary;
	}
	
	public boolean verifyNotary( PublicKey publicKey, Signature sig ) throws InvalidKeyException, SignatureException{
		sig.initVerify( publicKey );
		sig.update( this.payload );
		return sig.verify( this.signatureNotary );
	}
	
	
	
	/**
	 * @param args
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		TripleContract testContract = new TripleContract("E PLURIBUS UNUM.");

	    //
	    // generate an RSA keypair
	    System.out.println( "\nStart generating RSA key" );
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024);
	    
	    KeyPair intiatorKey = keyGen.generateKeyPair();
	    KeyPair recipientKey = keyGen.generateKeyPair();
	    KeyPair notaryKey = keyGen.generateKeyPair();

	    System.out.println( "Finish generating RSA keys" );
	    //
	    // get a signature object using the MD5 and RSA combo
	    // and sign the plaintext with the private key,
	    // listing the provider along the way
	    
	    Signature sig = Signature.getInstance("MD5WithRSA");
	    // creates the cipher
	    
	    // sign all three
	    testContract.signInitiator(intiatorKey.getPrivate(), sig);
	    testContract.signRecipient(recipientKey.getPrivate(), sig);
	    testContract.signNotary(notaryKey.getPrivate(), sig);
	    
	    try {
		      if ( testContract.verifyInitiator(intiatorKey.getPublic(), sig) ) {
		        System.out.println( "Initiator Signature verified" );
		      } else System.out.println( "Signature failed" );
		    } catch (SignatureException se) {
		      System.out.println( "Signature failed" );
		    }
	    

	}

}
