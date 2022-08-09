# Solution - modernism

- We need a way to exfiltrate flag contents
- in order to read a crossorigin page, we can attempt to load it as some sort of asset that we can access properties of
- a documented method to do this, is to load it as a script or stylesheet. if the script sets any variables or calls any methods, we can intercept that in our crossorigin page. in the case of a stylesheet, we could call getComputedStyle()
- now the challenge is to turn the file into valid javascript, this isn't entirely trivial as we only control the prefix, not the suffix at all
- we can utilize a byte order mark (BOM) prefix in order for the resource to be interpreted as UTF16
- this results in the flag turning into random valid chinese characters, the character range of the flag will thankfully lead to this always being a valid javascript identifier
- our payload could be something like `++window.`, which would cause the flag to be set on the window object
- final payload: `FEFF002B002B00770069006E0064006F0077002E`
- in crossorigin page: 
```js
encutf16=(s)=>[...s].flatMap(c=>[String.fromCharCode(c.charCodeAt(0)>>8),String.fromCharCode(c.charCodeAt(0)&0xff)]).join('')
Object.getOwnPropertyNames(window).map(x=>encutf16(x)).find(x=>x.startsWith('uiuctf{'))
```


note: the approach used in precisionism does *not* seem to viable here due to no suffix making it difficult to consturct an image that parses correctly
