# Writeup - Magic Book Challenge

## Description
The photo shows a book with a spell and a note that suggests an audio file is hidden in the image.

## Solution
1. Audio file extraction
The audio file has been hidden in the image using steganography. To extract it from the `Magic-Book.bmp` file, we will use the **Steghide** tool.  
The command to extract: \\ 
`steghide --extract -sf Magic-Book.bmp`.

2. Play the audio file
After extracting the audio file, we notice that the audio is played backwards. In order to listen to it properly, it needs to be reversed in time. This can be done in the Audacity program:

- Load the audio file into the program.
- Select Effects → Invert.
- Play the file to hear the correct sound.

3. Decrypt a fragment of a spell
After inverting the recording, you can hear a fragment of the spell that is blurred in the picture. This fragment contains the word “spectrogram”, which indicates that you need to analyze the audio file as a spectrogram.

4. Spectogram analysis
The next step is to view the audio file as a spectrogram in Audacity:

- Go to the View → Spectrogram tab.
- Zoom in on the spectrogram view to see the hidden message.
- There is a hidden flag in the spectrogram:

`zeroday{5p3ctr0gram!}`
