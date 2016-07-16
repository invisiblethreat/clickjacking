# clickjacking.go
Detect if a webserver is implementing clickjack protection using the header
`X-Frame-Options`.

### Usage
```
$ ./clickjack -h
Usage of ./clickjack:
  -f string
        This is the file that is read and processed (default "urls.txt")
  -file string
        This is the file that is read and processed (default "urls.txt")
```

### Example using urls.txt(default)
```
$ ./clickjack
2 sites returned results, 1 sites had errrors.
Sites vulnerable: 1
Sites Protected : 1
50 % of sites tested implemented clickjack protection.

The following sites had issues being retreived:
         https://asdfasdf.asdfasdf.adsfasdf.com
```

### Example using big.txt
```
$ ./clickjack -f big.txt
500 sites returned results, 3 sites had errrors.
Sites vulnerable: 344
Sites Protected : 156
31.2 % of sites tested implemented clickjack protection.

The following sites had issues being retreived:
         http://logc204.xiti.com/go.click?xts=453041&s2=14&p=homepage::kundendefault::index::button-mehr-info&clic=N&type=click
         http://liuliang.ok365.com/
         http://www.icann.org/en/registrars/registrant-rights-responsibilities-en.htm
```

### Caveats
* Does not account for redirects(note icann.org above, it returns a 302.)
