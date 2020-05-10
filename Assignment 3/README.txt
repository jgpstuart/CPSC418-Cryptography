Submitted by: Jeremy Stuart (00311644)
CPSC418, Winter 2020
University of Calgary
Assignment 3

Description:
This suite of files simulate a complete TLS protocol which provides end-to-end encryption over a network where a client and a server are exchanging a file.  By simulating a trusted third party (hereafter "TTP") in the TTP.py file, the server is issued a certificate and the client is able to verify the server's identity - which provides authentication - and the data is encrypted using keys that are exchanged which provides privacy.  Finally, the data that is exchanged is done using HMAC so that there is data integrity as well.  

1) Server.py: Acts as a server which fetches a certificate from the TTP, sends the certificate to the client, and then initiates a key exchange and file transfer with the client.
2) Client.py: Simulates a client in the TLS simulation.  The Client connects to the TTP and obtains the TTP's public keys which it uses to authenticate the server's certificate.  The client then conencts to the server, and then exchanges values and performs calculations needed to arrive at a shared key with the Server and then transfer a file using the shared key.
3) TTP.py: Simulates a trusted third party that issues a certificate to the Server.  The TTP also issues public key information to the Client which then uses the public key to check the server's certificate.
4) RSA.py: Simulates an RSA key generator.  The Client, Server, and TTP all call on the RSA file to generate their public and private keys which are used throughout the key exchange.
5) README.txt


Known bugs:
The client does not pass the autograder.  The server file currently passes all tests, but my client (which produces the expected output when working with my server) only gets 5/7 on the autograder.  The autograder is saying that something is mangled in transmission (and that I'm not using HMAC-SHA3-256...which I am).  Likely an issue with where I join values somewhere!


Post deadline update!
12:09PM: I switched from HMAC-SHA3-256 to just hashing the tag, and got an extra 1.5 marks (which was submitted 6 minutes after the deadline).  I'm still loosing marks beacuse "No evidence the file was successfully sent" and I'm not sure what to make of that.  My best guess is that it's something to do with the print statement about the file being sent.