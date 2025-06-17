from Crypto.Cipher import AES
from os import urandom

def szyfrowanie(plik):

    with open(plik, 'r') as f:
        wiadomosc = f.read()

    #wydobywanie nazwy pliku (do tworzenia zaszyfrowanej wersji)
    plik = plik.split('/')[-1]
    plik = plik.split('.')[0]

    klucz = urandom(16)
    obiekt = AES.new(klucz, AES.MODE_OCB)

    #encrypt_and_digest zwraca w postaci bitow: zaszyfrowana wiadomosc
    #oraz tag potrzebny do weryfikacji przy odszyfrowywaniu
    wiadomosc_zaszyfrowana, tag = obiekt.encrypt_and_digest(wiadomosc.encode('utf-8'))

    #sprawdzanie czy nonce - wymagany element metody OCB, ma dlugosc 15 bajtow
    assert len(obiekt.nonce) == 15

    #zwracanie uzytkownikowi klucza AES do odszyfrowywania wiadomosci (w formacie szesnastkowym)
    with open(f'{plik}_klucz.txt', 'w') as f:
        f.write(klucz.hex())

    #zapisywanie zaszyfrowanej wiadomosci do pliku binarnego
    with open(f'{plik}_zaszyfrowany.bin', 'wb') as f:
        f.write(tag)
        f.write(obiekt.nonce)
        f.write(wiadomosc_zaszyfrowana)


def deszyfrowanie(klucz, plik):

    with open(plik, 'rb') as f:
        tag = f.read(16)
        nonce = f.read(15)
        wiadomosc_zaszyfrowana = f.read()

    # wydobywanie nazwy pliku (do tworzenia odszyfrowanej wersji)
    plik = plik.split('/')[-1]
    plik = plik.split('.')[0]

    #konwersja klucza z szesnastkowego na binarny
    klucz = bytes.fromhex(klucz)

    obiekt = AES.new(klucz, AES.MODE_OCB, nonce=nonce)

    #proba deszyfracji pliku
    #w tej metodzie porownywany jest tag wiadomosci, by sprawdzic czy byla modyfikowana
    try:
        wiadomosc = obiekt.decrypt_and_verify(wiadomosc_zaszyfrowana, tag)

        with open(f'{plik}_odszyfrowany.txt', 'w') as f:
            f.write(wiadomosc.decode())
    except ValueError:
        print("Uwaga! Plik zostal zmieniony!")

#hub wyborow
while True:
    opcja = input("Co chcesz zrobić? Podaj numer polecenia. Zakodowac plik (1), Zdeszyfrowac plik (2)\n")

    if opcja == "1":
        plik = input("Podaj sciezke do pliku.\n")
        szyfrowanie(plik)
        break
    elif opcja == "2":
        klucz = input("Podaj klucz do deszyfracji pliku.\n")
        plik = input("Podaj sciezke do pliku.\n")
        deszyfrowanie(klucz, plik)
        break
    else:
        print("Podano zla opcje! Sprobuj jeszcze raz.")
