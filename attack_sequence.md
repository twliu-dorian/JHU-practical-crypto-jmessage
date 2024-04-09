# Attack Sequence

## Pre-conditions

1. User Charlie is sending a message `Hi` to Alice
2. Attacker can intercept the ciphertext in the communication channel
3. Alice runs in headless mode

## Attack sequence

### Signature bypass

1. intercept the message
2. attack creates its' own sigPK, sigSK
3. attacke sends `C1` || `modified C2` and signs with its own sigSK to bypass signature check

### Padding Oracle attack

1. attack sets its username to `charliea`
2. attacker modifies the delimiter `:` (0x3A) and finds the correct byte B to let B(ASCII) xor 0x3A = a(ASCII)
3. attacker sends the modified ciphertext to Alice and receives an error, because Alice can not find the delimiter `:` during the decryption process. To know this error from the attackers perspective, it can not receive a read receipt
4. the attacker starts to decrypt the message one byte at a time
5. the attacker finds the encrypted `enc(H)` and find a byte `B` xor `enc(H)` = `enc(:)`, to find the correct B, try 0000000-1111111 bacause in the ASCII (American Standard Code for Information Interchange) character encoding scheme, there are a total of 128 characters.

```
if the correct B:
To get the value of H based on the given equations, we can rearrange the terms and solve for H.

Given:
B xor enc(H) = enc(:)
enc(H) = K xor H
enc(:) = K xor :

Substituting enc(H) and enc(:) in the first equation:
B xor (K xor H) = K xor :

Using the XOR property (A xor B) xor B = A, we can eliminate K from both sides:
(B xor (K xor H)) xor K = (K xor :) xor K
B xor ((K xor H) xor K) = :

Since (K xor H) xor K = H (due to the XOR property), we get:
B xor H = :

Rearranging to solve for H:
H = B xor :

```

6. the attacker decrypts one byte using `B` xor `:` = `H`
7. create another user `charlieaa` and repeat steps from 2.-6.

### CRC32 fix

1. Use the CRC linear property: CRC(0) xor CRC(X) xor CRC(Y) = CRC(X xor Y)

```
X looks like:
```

2. len(CRC(0)) = max(len(CRC(X), len(CRC(Y)))
3. 0 = hex(0x00, 0x00, ...)
4. X is original plain text(M') = (username || 0x3A || M)
5. We need to find Y such that CRC(0) xor CRC(X) xor CRC(Y) = CRC(X xor Y) which is the correct CRC for the modified cipher text

This is origin C2 Bytes: [139 161 126 121 17 138 58 171 26 101 118 37 236 112 103]
This is new C2 Bytes: [139 161 126 121 17 138 58 240 72 101 118 37 236 112 103]
decrypted message: h
This is origin C2 Bytes: [139 161 126 121 17 138 58 240 72 101 118 37 236 112 103]
This is new C2 Bytes: [139 161 126 121 17 138 58 240 19 54 118 37 236 112 103]
decrypted message: hi

```go=
func performPaddingOracleAttack(ciphertext CiphertextStruct, victimUsername string, username string, privKey PrivKeyStruct) string {
	//Victim2
	SenderUsername := "charlie"
	// Decode the C2 component from base64
	c2Bytes, err := base64.StdEncoding.DecodeString(ciphertext.C2)
	if err != nil {
		fmt.Printf("Failed to decode C2: %v\n", err)
		return ""
	}

	ciphertextLength := len(c2Bytes)

	// Create a slice to store the decrypted plaintext
	plaintext := make([]byte, ciphertextLength-4-len(SenderUsername)-1)

	//Xoring B and initiate to 0
	XoringB := make([]byte, ciphertextLength-4)

	for i := range XoringB {
		XoringB[i] = 0x00
	}

	// maSenderUsernameke delimiter to a
	XoringB[len(SenderUsername)] = 0x5B

	//Index to bruteforce

	// Bruteforce the current character by XORing with 2^7 bits
	modifiedCiphertext := make([]byte, ciphertextLength)
	for i := 0; i < len(plaintext); i++ {
		forceI := len(SenderUsername) + 1 + i
		for j := 0; j < 128; j++ {
			fmt.Println("This is the counter", j)
			copy(modifiedCiphertext, c2Bytes)
			XoringB[forceI] = byte(j)

			//Fixcrc
			modifiedCiphertext = FixCRC(modifiedCiphertext, XoringB)

			fmt.Println("This is the modified ciphertext", modifiedCiphertext)
			// Encode the modified ciphertext back to base64
			modifiedC2 := base64.StdEncoding.EncodeToString(modifiedCiphertext)

			// Create a new replay with the modified C2
			replay := ciphertext
			replay.C2 = modifiedC2

			// Sign the modified ciphertext using Mallory's private key
			replay.Sig = signMessage(replay, privKey)

			// Send the modified ciphertext to Alice
			jsonMessage, err := json.Marshal(replay)
			if err != nil {
				fmt.Printf("Failed to marshal modified ciphertext: %v\n", err)
				continue
			}
			fmt.Println("modified Cipher Text is", string(jsonMessage))
			fmt.Println("Sending to username", username)
			err = sendMessageToServer1(username, victimUsername, jsonMessage, 0)
			if err != nil {
				fmt.Printf("Failed to send message to Alice: %v, sending message to this username %s \n", err, username)
				continue
			}

			// Wait for a short duration (e.g., 100ms) to allow Alice to process the message
			time.Sleep(300 * time.Millisecond)

			// Check if a read receipt was received from Alice
			messageList, err := getMessagesFromServer1(privKey, username)
			if err != nil {
				fmt.Printf("Failed to retrieve messages: %v\n", err)
				continue
			}

			readReceiptReceived := false
			for _, message := range messageList {
				if message.ReceiptID != 0 && message.From == victimUsername {
					readReceiptReceived = true
					fmt.Println("Got a Read Reciept for this j value", j)
					break
				}
			}

			if readReceiptReceived {
				// The current character decrypted to 0x3A (':')
				plaintext[i] = byte(j) ^ 0x3A
				fmt.Println("Found PLaintext: ", string(plaintext[i]))
				XoringB[forceI] = plaintext[i] ^ 0x61
				fmt.Print("Xoring : ")
				fmt.Println(XoringB)
				break
			}
		}
		username = username + "a"
		fmt.Println("New username", username)
		apiKey := ""
		privKey, apiKey = Reregister(username)
		fmt.Println("New API KEY", apiKey)
	}

	return string(plaintext)
}
```
