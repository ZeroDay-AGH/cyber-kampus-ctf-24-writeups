
Solve:

1. exiftool audio
```
exiftool spell.wav
ExifTool Version Number         : 12.40
File Name                       : spell.wav
Directory                       : .
File Size                       : 22 MiB
File Modification Date/Time     : 2024:12:01 20:22:19+01:00
File Access Date/Time           : 2024:12:01 20:24:02+01:00
File Inode Change Date/Time     : 2024:12:01 20:23:41+01:00
File Permissions                : -rwxrwxrwx
File Type                       : WAV
File Type Extension             : wav
MIME Type                       : audio/x-wav
Encoding                        : Microsoft PCM
Num Channels                    : 2
Sample Rate                     : 48000
Avg Bytes Per Sec               : 192000
Bits Per Sample                 : 16
Date Created                    : 11111111111111
Software                        : magic wand (libsndfile-1.0.31)
Track Number                    : 14230
ID3 Size                        : 197
Artist                          : Dr. Sponge
Track                           : 14230
User Defined Text               : (Software) magic wand
Warning                         : [minor] Frame 'TDRC' is not valid for this ID3 version
Recording Time                  : 11111111111111
Genre                           : Spell
Comment                         : captured at 14.230MHz
Duration                        : 0:01:58
```

Comment -> Google '14.230MHz' -> SSTV

2. use qsstv to decode the image

3. image contains a discord invite link: [discord.gg/EGAMBb2z7r](https://discord.gg/EGAMBb2z7r)

4. join the discord, use discord api to get hidden channels (REDACTED = discord Authorization token can be found after opening dev tool and discord in browser, going to network tab, refreshing the page, inspecting @me request for example):


```
curl -X GET "https://discord.com/api/v9/guilds/1308319769929318400/channels" -H "Authorization: REDACTED"
```

```
curl -X GET "https://discord.com/api/v9/guilds/1308319769929318400/channels" -H "Authorization: REDACTED"
[{"id":"1308319770503811134","type":0,"last_message_id":"1308474233688555565","flags":0,"guild_id":"1308319769929318400","name":"casual_chat_for_wizards","parent_id":null,"rate_limit_per_user":0,"topic":null,"position":0,"permission_overwrites":[{"id":"1308319769929318400","type":0,"allow":"0","deny":"377957124097"}],"nsfw":false,"icon_emoji":{"id":null,"name":"\ud83d\udc4b"},"theme_color":null},{"id":"1308321009438556261","type":0,"last_message_id":"1308474084828516412","flags":0,"guild_id":"1308319769929318400","name":"very_secret_chat_for_shadow_wizards","parent_id":null,"rate_limit_per_user":0,"topic":"zeroday{now_you_c4n_join_5hadow_wizard_gang}","position":1,"permission_overwrites":[{"id":"1308319769929318400","type":0,"allow":"0","deny":"1024"},{"id":"1308320133437067334","type":0,"allow":"1024","deny":"0"}],"nsfw":false}]
```

5. topic of 'very_secret_chat_for_shadow_wizards' -> flag: 
```
zeroday{now_you_c4n_join_5hadow_wizard_gang}
```