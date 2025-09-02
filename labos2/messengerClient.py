import pickle
import os
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec

class MessengerClient:
    """ Messenger client klasa

        Slobodno mijenjajte postojeće atribute i dodajte nove kako smatrate
        prikladnim.
    """

    def __init__(self, username, ca_pub_key):
        """ Inicijalizacija klijenta

        Argumenti:
        username (str) -- ime klijenta
        ca_pub_key     -- javni ključ od CA (certificate authority)
        conns          -- popis aktivnih konekcija s različitim klijentima
        dh_key_pair    -- inicijalni par ključeva Diffie-Hellman koje smo dobili metodom generate_certificate
        """

        self.username = username
        self.ca_pub_key = ca_pub_key
        self.conns = {}                 # aktivne konekcije s drugim klijentima,spremit će se 2 Key-a od 32 bajta, jedan za slanje i jedan za primanje
        self.dh_key_pair = ()           # inicijalni Diffie-Hellman par ključeva iz metode `generate_certificate` (public, private)
        self.dh_key_pair_conns = {}     # rječnik Diffie-Hellman za pohranjivanje Diffie-Hellman parova ključeva s kojim se komunicira
        self.key_root = {}              # rječnik key_root za pohranjivanje dijeljenih ključeva za svakog klijenta s kojim se komunicira
        self.dh_public_key = {}         # rječnik Diffie-Hellman za pohranjivanje javnih ključeva Diffie-Hellman s kojim se komunicira


    def generate_certificate(self):
        """ Generira par Diffie-Hellman ključeva i vraća certifikacijski objekt

        Metoda generira inicijalni Diffie-Hellman par kljuceva; serijalizirani
        javni kljuc se zajedno s imenom klijenta postavlja u certifikacijski
        objekt kojeg metoda vraća. Certifikacijski objekt moze biti proizvoljan (npr.
        dict ili tuple). Za serijalizaciju kljuca mozete koristiti
        metodu `public_bytes`; format (PEM ili DER) je proizvoljan.

        Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA te
        će tako dobiveni certifikat biti proslijeđen drugim klijentima.

        """

        private_key_dh = ec.generate_private_key(ec.SECP384R1(), default_backend())
        public_key_dh = private_key_dh.public_key()

        serialized_public_key_dh = public_key_dh.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.dh_key_pair = (public_key_dh, private_key_dh)  # inicijalizacija para kljuceva Diffie-Hellman
        return (serialized_public_key_dh, self.username)


    def receive_certificate(self, cert, signature):
        """ Verificira certifikat klijenta i sprema informacije o klijentu (ime
            i javni ključ)

        Argumenti:
        cert      -- certifikacijski objekt
        signature -- digitalni potpis od `cert`

        Metoda prima certifikacijski objekt (koji sadrži inicijalni
        Diffie-Hellman javni ključ i ime klijenta) i njegov potpis kojeg
        verificira koristeći javni ključ od CA i, ako je verifikacija uspješna,
        sprema informacije o klijentu (ime i javni ključ). Javni ključ od CA je
        spremljen prilikom inicijalizacije objekta.

        """

        try:
            self.ca_pub_key.verify(signature, pickle.dumps(cert), ec.ECDSA(hashes.SHA256()))  # Verificiraj certifikat koristeći javni ključ CA
        except Exception:
            raise Exception("netocan potpis")
        else:
            # Ako verifikacija prođe, izvrši sljedeće korake
            serialized_pub_key, user_name = cert[0], cert[1]  # Dohvati ime i serijalizirani javni ključ iz certifikata
            self.conns[user_name] = [None, None]  # Inicijalizacija nove veze bez ključeva
            self.dh_public_key[user_name] = load_der_public_key(serialized_pub_key)  # Spremi ime i deserializirani javni ključ
            self.key_root[user_name] = self.dh_key_pair[1].exchange(ec.ECDH(), self.dh_public_key[user_name])  # Generiraj i spremi dijeljenu tajnu kao Root Key
            self.dh_key_pair_conns[user_name] = (self.dh_key_pair[0], self.dh_key_pair[1])  # Sprema klijentove vlastite Diffie-Hellman ključeve


    def send_message(self, username, message):
        """ Slanje poruke klijentu

        Argumenti:
        message  -- poruka koju ćemo poslati
        username -- klijent kojem šaljemo poruku `message`

        Metoda šalje kriptiranu poruku sa zaglavljem klijentu s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da klijent posjeduje vaš.
        Ako već prije niste komunicirali, uspostavite sesiju tako da generirate
        nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada šaljete poruku napravite `ratchet` korak u `sending`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji).  S novim
        `sending` ključem kriptirajte poruku koristeći simetrični kriptosustav
        AES-GCM tako da zaglavlje poruke bude autentificirano.  Ovo znači da u
        zaglavlju poruke trebate proslijediti odgovarajući inicijalizacijski
        vektor.  Zaglavlje treba sadržavati podatke potrebne klijentu da
        derivira novi ključ i dekriptira poruku.  Svaka poruka mora biti
        kriptirana novim `sending` ključem.

        Metoda treba vratiti kriptiranu poruku zajedno sa zaglavljem.

        """

        # uspostavljamo vezu ukoliko nije postojala
        if (self.conns[username][0] is None):

            # generiramo nove DH kljuceve
            private_key = ec.generate_private_key(ec.SECP384R1())
            public_key = private_key.public_key()
            self.dh_key_pair_conns[username] = (public_key, private_key) 

            # razmjena DH ključeva
            shared_secret_key = self.dh_key_pair_conns[username][1].exchange(ec.ECDH(), self.dh_public_key[username])
            
            keys = PBKDF2(shared_secret_key, self.key_root[username], 64, count=1000000, hmac_hash_module=SHA512)
            self.conns[username][0], self.key_root[username] = keys[:32], keys[32:] # Razdvajanje ključeva(inicijalni next Chain Key, Root Key)   

        serialized_public_key = self.dh_key_pair_conns[username][0].public_bytes( # Serijalizacija vlastitog javnog ključa u formatu DER
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # kod iz laba1
        keys = PBKDF2(self.conns[username][0], b'123', 64, count=1000000, hmac_hash_module=SHA512)
        message_key =  keys[32:]
        cipher = AES.new(message_key, AES.MODE_GCM)     # enkripcija
        self.conns[username][0] = keys[:32]   # pomak sending lanca 
        return (cipher.encrypt(bytes(message, 'UTF-8')) , serialized_public_key,cipher.digest(), cipher.nonce) #saljemo kriptiranu poruku, serijalizirani kljuc, tag i nonce


    def receive_message(self, username, message):
        """ Primanje poruke od korisnika

        Argumenti:
        message  -- poruka koju smo primili
        username -- klijent koji je poslao poruku

        Metoda prima kriptiranu poruku od klijenta s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da je klijent izračunao
        inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz vašeg
        certifikata.  Ako već prije niste komunicirali, uspostavite sesiju tako
        da generirate nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji) koristeći
        informacije dostupne u zaglavlju i dekriptirajte poruku uz pomoć novog
        `receiving` ključa. Ako detektirate da je integritet poruke narušen,
        zaustavite izvršavanje programa i generirajte iznimku.

        Metoda treba vratiti dekriptiranu poruku.

        """
        cipher_text , new_dhPublic_key , tag , nonce = message

        # Provjeravamo je li primljeni Diffie-Hellman javni ključ jednak trenutnom,a inače radimo pomak
        if (new_dhPublic_key != self.dh_public_key[username]):
            
            # Diffie-Hellman razmjena ključeva za primanje
            deserialized_public_key = load_der_public_key(new_dhPublic_key) # Deserializacija javnog ključa
            keys = PBKDF2(self.dh_key_pair_conns[username][1].exchange(ec.ECDH(),   #Izvođenje Diffie-Hellman razmjene ključeva za primanje
             deserialized_public_key), self.key_root[username], 64, count=1000000, hmac_hash_module=SHA512)  # Derivacija ključeva za primanje
            self.conns[username][1], self.key_root[username] = keys[:32],keys[32:] # Razdvajanje na Chain Key za primanje i novi Root Key

            #Diffie-Hellman razmjena ključeva za slanje:
            private_key = ec.generate_private_key(ec.SECP384R1())
            self.dh_key_pair_conns[username] = (private_key.public_key() , private_key) # novi Diffie-Hellman par kljuceva

            keys = PBKDF2(self.dh_key_pair_conns[username][1].exchange(ec.ECDH(),    #Izvođenje Diffie-Hellman razmjene ključeva za slanje
             deserialized_public_key), self.key_root[username], 64, count=1000000, hmac_hash_module=SHA512) #Derivacija ključeva za slanje
            self.conns[username][0], self.key_root[username]  = keys[:32] , keys[32:]   # Razdvajanje na Chain Key za slanje i novi Root Key 
            self.dh_public_key[username] = new_dhPublic_key # Postavljanje javnog ključa za Diffie-Hellman     

        #kod iz prvog labosa
        curr_chain_key_rec = self.conns[username][1]       # Postavljanje trenutnog receiving Chain Key-a

        keys = PBKDF2(curr_chain_key_rec, b'123', 64, count=1000000, hmac_hash_module=SHA512)
        message_key = keys[32:]  # Razdvajanje izvedenih ključeva na novi receiving Chain Key i novi Message Key
        self.conns[username][1] = keys[:32]                   # Racunanje pomaka receving lanca 

        return AES.new(message_key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(cipher_text, received_mac_tag=tag).decode('utf-8') # Dekripcija 


def main():
    pass

if __name__ == "__main__":
    main()
