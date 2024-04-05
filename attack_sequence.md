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
2. len(CRC(0)) = max(len(CRC(X), len(CRC(Y)))
3. 0 = hex(0x00, 0x00, ...)
4. X is original plain text(M') = (username || 0x3A || M)
5. We need to find Y such that CRC(0) xor CRC(X) xor CRC(Y) = CRC(X xor Y) which is the correct CRC for the modified cipher text
