function Full-URLEncode {
    param (
	    [Parameter(Mandatory=$true,ValueFromPipeline)]
        [string]$INTEXT
	)
    [string]$OUTTEXT = ""
    for ($i = 0; $i -lt $INTEXT.Length; $i++) {
        [string]$TEXT = $INTEXT[$i]
		if ($TEXT -ceq ' ') { $TEXT = "%20"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '!') { $TEXT = "%21"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '"') { $TEXT = "%22"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '#') { $TEXT = "%23"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '$') { $TEXT = "%24"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '%') { $TEXT = "%25"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '&') { $TEXT = "%26"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq "'") { $TEXT = "%27"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '(') { $TEXT = "%28"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq ')') { $TEXT = "%29"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '*') { $TEXT = "%2A"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '+') { $TEXT = "%2B"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq ',') { $TEXT = "%2C"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '-') { $TEXT = "%2D"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '.') { $TEXT = "%2E"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '/') { $TEXT = "%2F"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '0') { $TEXT = "%30"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '1') { $TEXT = "%31"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '2') { $TEXT = "%32"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '3') { $TEXT = "%33"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '4') { $TEXT = "%34"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '5') { $TEXT = "%35"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '6') { $TEXT = "%36"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '7') { $TEXT = "%37"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '8') { $TEXT = "%38"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '9') { $TEXT = "%39"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq ':') { $TEXT = "%3A"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq ';') { $TEXT = "%3B"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '<') { $TEXT = "%3C"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '=') { $TEXT = "%3D"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '>') { $TEXT = "%3E"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '?') { $TEXT = "%3F"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '@') { $TEXT = "%40"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'A') { $TEXT = "%41"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'B') { $TEXT = "%42"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'C') { $TEXT = "%43"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'D') { $TEXT = "%44"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'E') { $TEXT = "%45"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'F') { $TEXT = "%46"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'G') { $TEXT = "%47"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'H') { $TEXT = "%48"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'I') { $TEXT = "%49"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'J') { $TEXT = "%4A"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'K') { $TEXT = "%4B"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'L') { $TEXT = "%4C"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'M') { $TEXT = "%4D"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'N') { $TEXT = "%4E"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'O') { $TEXT = "%4F"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'P') { $TEXT = "%50"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'Q') { $TEXT = "%51"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'R') { $TEXT = "%52"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'S') { $TEXT = "%53"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'T') { $TEXT = "%54"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'U') { $TEXT = "%55"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'V') { $TEXT = "%56"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'W') { $TEXT = "%57"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'X') { $TEXT = "%58"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'Y') { $TEXT = "%59"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'Z') { $TEXT = "%5A"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '[') { $TEXT = "%5B"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '\') { $TEXT = "%5C"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq ']') { $TEXT = "%5D"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '^') { $TEXT = "%5E"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '_') { $TEXT = "%5F"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '``') { $TEXT = "%60"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'a') { $TEXT = "%61"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'b') { $TEXT = "%62"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'c') { $TEXT = "%63"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'd') { $TEXT = "%64"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'e') { $TEXT = "%65"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'f') { $TEXT = "%66"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'g') { $TEXT = "%67"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'h') { $TEXT = "%68"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'i') { $TEXT = "%69"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'j') { $TEXT = "%6A"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'k') { $TEXT = "%6B"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'l') { $TEXT = "%6C"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'm') { $TEXT = "%6D"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'n') { $TEXT = "%6E"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'o') { $TEXT = "%6F"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'p') { $TEXT = "%70"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'q') { $TEXT = "%71"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'r') { $TEXT = "%72"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 's') { $TEXT = "%73"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 't') { $TEXT = "%74"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'u') { $TEXT = "%75"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'v') { $TEXT = "%76"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'w') { $TEXT = "%77"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'x') { $TEXT = "%78"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'y') { $TEXT = "%79"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq 'z') { $TEXT = "%7A"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '{') { $TEXT = "%7B"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '|') { $TEXT = "%7C"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '}') { $TEXT = "%7D"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
        if ($TEXT -ceq '~') { $TEXT = "%7E"; $OUTTEXT = $OUTTEXT + $TEXT; continue }
    }
    return $OUTTEXT
}