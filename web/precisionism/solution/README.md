# Solution - precisionism

- We need a sidechannel to exfiltrate flag contents
- unfortunately, the BOM trick in modernism will not work since the characters in the suffix appended to the flag will always result in invalid JS (afaik)
- so, we need a different approach than a script tag
- One known xsleak is that some HTML elements leak some crossorigin data: https://xsleaks.dev/docs/attacks/element-leaks/
- e.g. if you load a crossorigin image, its height and width can be read
- the solution idea is simple, we come up with a prefix s.t. the resource is interpreted as an image, and the flag contents are reflected in the height/width properties
- `\x00\x00\x01\x00\x02\x00\x01\x01\x00\x00\x01\x00\x20\x00\x68\x04\x00\x00\x26\x00\x00\x00` works! it is an ICO file with two entries, we strip bytes from the end to read more of the flag
- this fileformat only reliably lets you exfiltrate 8-9 bytes. luckily that is all we need


```js
getWidth = async (url)=>{i=new Image();i.src=url;await i.decode();document.body.appendChild(i);return i.width}
0x69 === await getWidth("data:text/html;base64,"+btoa("\x00\x00\x01\x00\x02\x00\x01\x01\x00\x00\x01\x00\x20\x00\x68\x04\x00\x00\x26\x00\x00\x00\x69"+"PADDING".repeat(10))) // true
```


sidenote:
- another interesting prefix is `\x52\x49\x46\x46\x1c\x0c\x00\x00\x57\x41\x56\x45\x66\x6d\x74\x20\x10\x00\x00\x00\x01\x00\x01\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x08\x00\x64\x61\x74\x61\xae\x0b\x00\x00` (WAV). any bytes appended will increase audio.duration by 1
