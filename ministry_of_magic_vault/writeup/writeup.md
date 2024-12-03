# Ministry of magic vault

1. After entering random login credentials, the following message will appear:
`We only accept corrspondency in out office in London`
To bypass this security feature, set your browser location to London
or any of the following:
- `latitude 51 -- 52`
- `longtitude -0.13 -- -0.12`
<br/>
The easiest way to do this is through the “sensors” loader in Google Chrome, but the location data is sent in a POST request, so you can also modify it this way
![chrome](image.png)
![burpsuite](image-1.png)
2. After bypassing the previous protection and reentering random data, the following message will be displayed:
`We only accept requests delivered by owls`
You need to change value of `User-Agent` to `Owl` or `owl`

3. Another error:
`We demand thy correspondence be written in proper british English`
Change `Accept_Language` header value to `en-GB`
<br/>
If you used other browser than chrome to set localization, then this header would be set automatically

4. Another error:
`Invalid login credentials`
After entering the /robots.txt subsite the /passes.txt will be displayed.
Then on the /passes.txt you can find login credentials
`hpotter@mmin.gov.uk`
`3d2QGYu2V8DLo)HhyHmzEQzWaoH`
