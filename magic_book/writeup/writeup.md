# Writeup - Magic Book Challenge

## Opis
Zdjęcie przedstawia książkę z zaklęciem oraz nutą, która sugeruje, że w obrazie ukryty jest plik audio.

## Rozwiązanie
1. Ekstrakcja pliku audio
Plik audio został ukryty w obrazie przy użyciu steganografii. Aby wydobyć go z pliku `Magic-Book.bmp`, użyjemy narzędzia **Steghide**.  
Komenda do ekstrakcji:  
`steghide --extract -sf Magic-Book.bmp`
2. Odtworzenie pliku audio
Po wydobyciu pliku audio zauważamy, że dźwięk jest odtwarzany od tyłu. Aby go poprawnie odsłuchać, należy odwrócić go w czasie. Można to zrobić w programie Audacity:

Załaduj plik audio do programu.
Wybierz opcję Efekty → Odwróć.
Odtwórz plik, aby usłyszeć poprawny dźwięk.
3. Odszyfrowanie fragmentu zaklęcia
Po odwróceniu nagrania można usłyszeć fragment zaklęcia, które jest zamazane na zdjęciu. Fragment ten zawiera słowo "spektogram", co wskazuje na konieczność analizy pliku audio w postaci spektrogramu.

4. Analiza spektrogramu
Kolejnym krokiem jest wyświetlenie pliku audio w formie spektrogramu w Audacity:

Przejdź do zakładki Widok → Spektrogram.
Powiększ widok spektrogramu, aby dostrzec ukrytą wiadomość.
W spektrogramie znajduje się ukryta flaga:
`zeroday{5p3ctr0gram!}`