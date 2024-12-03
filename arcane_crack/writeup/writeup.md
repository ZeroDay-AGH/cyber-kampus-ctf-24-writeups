The task consists of 4 parts: cracking the hashes in the 3 scrolls and unlocking the door. In the task description there are some clues that help in solving the challenge:

1. Each lock (behind a bcrypt) is protected with some password from each scroll. This means, that if we crack one scroll, we have a 100% success rate to open one lock.

2. The task description mentions a popular hash cracking rule - OneRuleToRuleThemAll

The scrolls consists of 51 hashes each, and these hashes are NTLM (scroll 1), MD5 (scroll 2) and SHA256 (scroll 3). The NTLM and MD5 hashes look the same, so only after a successful crack we can disambiguate between them. This can be done with a very simple brute force/mask attack, which can also highlight the source of the passwords.

The first scroll consist of passwords taken directly from a very popular rockyou.txt dictionary. To solve this challenge, all you need to do is launch a dictionary attack. One of the passwords is also the password behind the first bcrypt.

The second scroll consists of passwords taken from first scroll (rockyou.txt), but mangled with the rules from OneRuleToRuleThemAll. To solve this challenge, all you need to do is launch a dictionary attack with rules. One of the passwords is also the password behind the second bcrypt. 

The thirds scroll consists of passwords taken from second scroll, but mangled again with the rules from OneRuleToRuleThemAll. This is to highlight a useful trick while cracking the passwords from one source, when already cracked passwords can be an effective feed to another round of cracking. Hashcat even has the dedicated switch of --loopback that could be helpful in such cases. To solve this challenge, all you need to do is launch a dictionary attack with rules again. One of the passwords is also the password behind the third bcrypt.

Having all scrolls hashes cracked, a simple dictionary attack based with scroll-cracked passwords can successfully reveal all bcrypt passwords. The flag is a combinations of the bcrypt cracked passwords.
