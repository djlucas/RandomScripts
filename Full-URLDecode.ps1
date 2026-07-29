function Full-URLDecode {
    param (
     [Parameter(Mandatory=$true,ValueFromPipeline)]
        [string]$INTEXT
    )
	for ($i = 0; $i -lt $INTEXT.Length; $i = $i + 3) {
	    $TEXT = $INTEXT[$i] + $INTEXT[$i + 1] + $INTEXT[$i + 2]
        if ($TEXT -ceq "%20") { $TEXT = ' '; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%21") { $TEXT = '!'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%22") { $TEXT = '"'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%23") { $TEXT = '#'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%24") { $TEXT = '$'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%25") { $TEXT = '%'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%26") { $TEXT = '&'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%27") { $TEXT = "'"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%28") { $TEXT = '('; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%29") { $TEXT = ')'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%2A") { $TEXT = '*'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%2B") { $TEXT = '+'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%2C") { $TEXT = ' '; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%2D") { $TEXT = '-'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%2E") { $TEXT = '.'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%2F") { $TEXT = '/'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%30") { $TEXT = '0'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%31") { $TEXT = '1'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%32") { $TEXT = '2'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%33") { $TEXT = '3'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%34") { $TEXT = '4'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%35") { $TEXT = '5'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%36") { $TEXT = '6'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%37") { $TEXT = '7'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%38") { $TEXT = '8'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%39") { $TEXT = '9'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%3A") { $TEXT = ':'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%3B") { $TEXT = ';'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%3C") { $TEXT = '<'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%3D") { $TEXT = '='; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%3E") { $TEXT = '>'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%3F") { $TEXT = '?'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%40") { $TEXT = '@'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%41") { $TEXT = 'A'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%42") { $TEXT = 'B'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%43") { $TEXT = 'C'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%44") { $TEXT = 'D'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%45") { $TEXT = 'E'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%46") { $TEXT = 'F'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%47") { $TEXT = 'G'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%48") { $TEXT = 'H'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%49") { $TEXT = 'I'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%4A") { $TEXT = 'J'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%4B") { $TEXT = 'K'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%4C") { $TEXT = 'L'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%4D") { $TEXT = 'M'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%4E") { $TEXT = 'N'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%4F") { $TEXT = 'O'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%50") { $TEXT = 'P'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%51") { $TEXT = 'Q'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%52") { $TEXT = 'R'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%53") { $TEXT = 'S'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%54") { $TEXT = 'T'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%55") { $TEXT = 'U'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%56") { $TEXT = 'V'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%57") { $TEXT = 'W'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%58") { $TEXT = 'X'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%59") { $TEXT = 'Y'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%5A") { $TEXT = 'Z'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%5B") { $TEXT = '['; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%5C") { $TEXT = '\'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%5D") { $TEXT = ']'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%5E") { $TEXT = '^'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%5F") { $TEXT = '_'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%60") { $TEXT = '``'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%61") { $TEXT = 'a'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%62") { $TEXT = 'b'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%63") { $TEXT = 'c'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%64") { $TEXT = 'd'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%65") { $TEXT = 'e'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%66") { $TEXT = 'f'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%67") { $TEXT = 'g'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%68") { $TEXT = 'h'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%69") { $TEXT = 'i'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%6A") { $TEXT = 'j'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%6B") { $TEXT = 'k'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%6C") { $TEXT = 'l'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%6D") { $TEXT = 'm'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%6E") { $TEXT = 'n'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%6F") { $TEXT = 'o'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%70") { $TEXT = 'p'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%71") { $TEXT = 'q'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%72") { $TEXT = 'r'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%73") { $TEXT = 's'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%74") { $TEXT = 't'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%75") { $TEXT = 'u'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%76") { $TEXT = 'v'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%77") { $TEXT = 'w'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%78") { $TEXT = 'x'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%79") { $TEXT = 'y'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%7A") { $TEXT = 'z'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%7B") { $TEXT = '{'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%7C") { $TEXT = '|'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%7D") { $TEXT = '}'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "%7E") { $TEXT = '~'; $OUTTEXT = $OUTTEXT + $TEXT; continue }
	    $OUTTEXT = $OUTTEXT + $TEXT
	}
    return $OUTTEXT
}