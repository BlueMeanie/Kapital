package com.bluemeanie.kapital.shared.core;

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

public class Message implements Serializable {

	// this is a just a simple message that is signable and serializable
	
	protected byte[] payload;
	
	protected byte[] initiatorSignature;
	
	/**
	 * @param args
	 * @return 
	 */
	
	Message(){}
	
	Message( String payload ){
		this.payload = payload.getBytes();
	}
	
	Message( byte[] payload ){
		this.payload = payload;
	}
	
	Message( String payload, PrivateKey signer ){
		
	}
	
	boolean isFullySigned() {
		return ( initiatorSignature != null );
	}
	
	public byte[] signInitiator( PrivateKey privateKey, Signature sig ) throws InvalidKeyException, SignatureException{
		sig.initSign( privateKey );
	    sig.update( payload );
	    this.initiatorSignature = sig.sign();
	    return this.initiatorSignature;
	}
	
	public boolean verify( PublicKey publicKey, Signature sig ) throws InvalidKeyException, SignatureException{
		sig.initVerify( publicKey );
		sig.update( this.payload );
		return sig.verify( this.initiatorSignature );
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, SignatureException {
		
	    Message testMessage = new Message("E PLURIBUS UNUM.");

	    //
	    // generate an RSA keypair
	    System.out.println( "\nStart generating RSA key" );
	    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024);
	    
	    KeyPair key = keyGen.generateKeyPair();
	    System.out.println( "Finish generating RSA key" );
	    //
	    // get a signature object using the MD5 and RSA combo
	    // and sign the plaintext with the private key,
	    // listing the provider along the way
	    
	    Signature sig = Signature.getInstance("MD5WithRSA");
	    // creates the cipher
	    
	    testMessage.signInitiator(key.getPrivate(), sig);
	    
	    try {
		      if ( testMessage.verify(key.getPublic(), sig) ) {
		        System.out.println( "Signature verified" );
		      } else System.out.println( "Signature failed" );
		    } catch (SignatureException se) {
		      System.out.println( "Signature failed" );
		    }
	    
	    
	}

}
