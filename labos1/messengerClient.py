#!/usr/bin/env python3
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
import secrets

class MessengerClient:
    """ Messenger client class

        Feel free to modify the attributes and add new ones as you
        see fit.

    """

    def __init__(self, username, max_skip=10):
        """ Initializes a client

        Arguments:
        username (str) -- client name
        max_skip (int) -- Maximum number of message keys that can be skipped in
                          a single chain
        conn (dict) -- rječnik koji sadrži podatke o aktivnim vezama. 
                key je username,a value su trenutni send i recv chain key
        salt -- konstanta koja se koristi u PBKDF2 funkciji. Ova konstanta je ista za cijelu vezu, ali različita za različite korisnike 
        Ns -- rječnik koji sadrži broj poslanih poruka za svaki korisnički račun 
        Nr --  rječnik koji sadrži broj poruka koje su primljene od svakog korisničkog računa.
        MKSKIPPED -- složena struktura rječnika u kojem je vanjski ključ korisničko ime,
        a unutarnji ključ je redni broj preskočene poruke, a vrijednost je ključ te poruke

        """

        self.username = username
        # Data regarding active connections.
        self.conn = {}
        # Maximum number of message keys that can be skipped in a single chain
        self.max_skip = max_skip
        self.MKSKIPPED = {}
        self.Ns = {}
        self.Nr = {}
        self.salt = secrets.token_bytes(16)


    def add_connection(self, username, chain_key_send, chain_key_recv):
        """ Add a new connection

        Arguments:
        username (str) -- user that we want to talk to
        chain_key_send -- sending chain key (CKs) of the username
        chain_key_recv -- receiving chain key (CKr) of the username

        """
        #inicjalizacija za connection
        kljucevi_1 = [chain_key_send, chain_key_recv]
        kljucevi_2 = {}
        self.Ns.setdefault(username, 0)
        self.Nr.setdefault(username, 0)
        self.conn.setdefault(username, kljucevi_1)
        self.MKSKIPPED.setdefault(username, kljucevi_2)


    
    def send_message(self, username, message):
        """ Send a message to a user

        Get the current sending key of the username, perform a symmetric-ratchet
        step, encrypt the message, update the sending key, return a header and
        a ciphertext.

        Arguments:
        username (str) -- user we want to send a message to
        message (str)  -- plaintext we want to send

        Returns a ciphertext and a header data (you can use a tuple object)

        """

        #dohvati ključ lanca za slanje
        curr_chain_key_send = self.conn[username][0]

        
        #Izvodi simetrični ratchet korak kako bi generirao sljedeći ključ lanca za slanje (next_chain_key_send)
        #i ključ poruke (message_key) iz trenutnog ključa lanca za slanje
        keys = PBKDF2(curr_chain_key_send, self.salt, 64, count=1000000, hmac_hash_module=SHA512)
        next_chain_key_send, message_key = keys[:32], keys[32:]

        # Vraćamo zaglavlje i šifrat poruke 
            # header = HEADER(state.DHs, state.PN, state.Ns)
            # state.Ns += 1
            # return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
        cipher = AES.new(message_key, AES.MODE_GCM)
        self.Ns[username] += 1 
        cipher_text = cipher.encrypt(bytes(message, 'UTF-8'))
        tag = cipher.digest()

        # Postavljamo novi ključ lanca za slanje za određenog korisnika
        self.conn[username][0] = next_chain_key_send

        return (self.salt, tag,  cipher.nonce ,  self.Ns[username],  cipher_text)        


    def skip_message_keys(self, until, username, salt):
        if  until   >  self.max_skip + self.Nr[username]:
            raise Exception

        while (self.Nr[username] + 1 < until) and (self.conn[username][1] != None):
            keys = PBKDF2(self.conn[username][1], salt, 64, count=1000000, hmac_hash_module=SHA512)
            self.MKSKIPPED[username][self.Nr[username]+1] = keys[32:]
            self.Nr[username] += 1
            self.conn[username][1] = keys[:32]


    def receive_message(self, username, message):
        """ Receive a message from a user

        Get the username connection data, check if the message is out-of-order,
        perform necessary symmetric-ratchet steps, decrypt the message and
        return the plaintext.

        Arguments:
        username (str) -- user who sent the message
        message        -- a ciphertext and a header data

        Returns a plaintext (str)

        """

        # Dohvaćamo podatke o vezi za određenog korisnika 
        salt, tag, nonce, Ns, cipher_text = message
        conn_data = self.conn[username]

        # Provjeravamo je li poruka izvan redoslijeda
        if Ns not in self.MKSKIPPED[username]:
            MessengerClient.skip_message_keys(self, Ns, username, salt)

            # Racunamo odgovarajuće ključeve za dešifriranje poruke
            keys = PBKDF2(conn_data[1], salt, 64, count=1000000, hmac_hash_module=SHA512)
            self.Nr[username] += 1
            self.conn[username][1] = keys[:32]
            # Dešifrirali poruku koristeći ključ poruke i vratili dešifrirani tekst 
            return AES.new(keys[32:], AES.MODE_GCM, nonce=nonce).decrypt_and_verify(cipher_text, received_mac_tag=tag).decode('utf-8')
        else:
            message_key = self.MKSKIPPED[username][Ns]
            del self.MKSKIPPED[username][Ns]
            return AES.new(message_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(cipher_text, received_mac_tag=tag).decode('utf-8')

