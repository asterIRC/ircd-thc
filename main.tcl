#!/usr/bin/env tclsh8.6

# TCL Chatd
# Inspired by RONSOR's chat daemon

package require md5
package require tls

array set dispnames {}
array set idents {}
array set rhostnames {}
array set hostnames {}
array set realnames {}
array set conpass {}
array set bans {}
array set rooms {}
array set servers {}
array set aways {}
array set servnick {}
array set modes {}

namespace eval config {
	array set me {}
	array set listen {}
	array set servers {}
	array set services {}
}

source ircd.conf

proc getfdbynick {nick} {
	foreach {fdp nic} [array get ::dispnames] {
		if {[string tolower $nick] == [string tolower $nic]} {
			return $fdp
		}
	}
}

proc getnickbyfd {nick} {
	foreach {fdp nic} [array get ::dispnames] {
		if {$nick == $fdp} {
			return $nic
		}
	}
}

proc makessl {fd} {
	global modes
	append modes($fd) "Z"
}

proc accept {chan addr port} {
	global hostnames dispnames idents realnames modes rhostnames aways
	set modes($chan) ""
	set idents($chan) ""
	set dispnames($chan) ""
	set realnames($chan) ""
	set rhostnames($chan) "$addr"
	set aways($chan) ""
	set ctr 0
	set xddr [string match "*:*" $addr]
	if {$xddr} {set wddr ":"} {set wddr "."}
	set yddr [split $addr "$wddr"]
	set zddr ""
	if {$xddr} {foreach {x y} $yddr {
		set w "$x"
		append w "$y"
		set srl [string length $w]
		set newad [string range [::md5::md5 -hex $w] 0 11]
		append zddr "$newad"
		append zddr $wddr
	} } { foreach {w} $yddr {
		set srl [string length w]
		set newad [string range [::md5::md5 -hex $w] 0 11]
		append zddr "$newad"
		append zddr $wddr
	} }
	append zddr "IP"
	set hostnames($chan) $zddr
	chan configure $chan -buffering line -blocking 0
	chan puts $chan ":$::config::me(server) 020 * :$::config::me(welcome)"
	chan event $chan readable [list client'unreg $chan $addr]
}

proc accept-ssl {chan addr port} {
	makessl $chan
	global hostnames dispnames idents realnames modes rhostnames aways
	set modes($chan) ""
	set idents($chan) ""
	set dispnames($chan) ""
	set realnames($chan) ""
	set rhostnames($chan) "$addr"
	set aways($chan) ""
	set ctr 0
	set xddr [string match "*:*" $addr]
	if {$xddr} {set wddr ":"} {set wddr "."}
	set yddr [split $addr "$wddr"]
	set zddr ""
	if {$xddr} {foreach {x y} $yddr {
		set w "$x"
		append w "$y"
		set srl [string length $w]
		set newad [string range [::md5::md5 -hex $w] 0 11]
		append zddr "$newad"
		append zddr $wddr
	} } { foreach {w} $yddr {
		set srl [string length w]
		set newad [string range [::md5::md5 -hex $w] 0 11]
		append zddr "$newad"
		append zddr $wddr
	} }
	append zddr "IP"
	set hostnames($chan) $zddr
	chan configure $chan -buffering line -blocking 1
	::tls::handshake $chan
	chan configure $chan -buffering line -blocking 0

	chan puts $chan ":$::config::me(server) 020 * :$::config::me(welcome)"
	chan event $chan readable [list client'unreg $chan $addr]
}

proc checknickname {nick} {
	set good "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]{}~/\|-_^()"
	set fishy "~-"
	if {[string is digit [string index $nick 0]]} {
		return 0
	}
	foreach {char} [split $fishy {}] {
		if {[string index $nick 0] == $char} {return 0}
	}
	foreach {letter} [split $nick {}] {
		foreach {goodchar} [split $good {}] {
			if {$letter == $goodchar} {
				set isgood 1
			} {
				set isgood 0
			}
		}
		if {$isgood} {} {return 1}
	}
	return 1
}


proc chgnick {chan nick} {
	if {![checknickname $nick]} {
		message'fd $chan $::config::me(server) [list "433" "$::dispnames($chan)" "$nick" "The nickname you have chosen is erroneous. Pick another."]
	}
	if {[getfdbynick $nick] != ""} {
		message'fd $chan $::config::me(server) [list "433" "$::dispnames($chan)" "$nick" "The nickname you have chosen is already in use. Pick another."]
	} {
		sendtoneigh $chan "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "NICK" "$nick"]
		set ::dispnames($chan) $nick
	}
}

proc sendtoneigh {chan src zarg} {
	global rooms
	set sendto [list $chan]
	message'fd $chan $src $zarg
	foreach {room} [array names rooms] {
		if {[lsearch -exact $rooms($room) "$chan"] == -1} {continue}
		foreach {niq} $rooms($room) {
			if {[lsearch -exact $sendto "$niq"] != -1} {continue}
			message'fd $niq $src $zarg
			lappend $sendto $niq
		}
	}
	puts stdout "[join $sendto "->"]"
}

proc sendtoneighchan {chan src zarg} {
	global rooms
	set sendto [list]
	#message'fd $chan $src $zarg
	foreach {room} [array names rooms] {
		if {[lsearch -exact $rooms($room) "$chan"] == -1} {continue}
		if {[string match "list,*" $room]} {continue}
		lappend sendto $room
		sendtochan $chan $room $src [lreplace $zarg [lsearch -exact $zarg "%chan"] [lsearch -exact $zarg "%chan"] $room]
	}
	puts stdout "[join $sendto "->"]"
}

proc sendtoneighbut {chan src zarg} {
	global rooms
	set sendto [list]
	#message'fd $chan $src $zarg
	foreach {room} [array names rooms] {
		if {[lsearch -exact $rooms($room) "$chan"] == -1} {continue}
		foreach {niq} $rooms($room) {
			if {[lsearch -exact $sendto "$niq"] != -1} {continue}
			if {$niq == $chan} {continue}
			message'fd $niq $src $zarg
			lappend $sendto $niq
		}
	}
	puts stdout "[join $sendto "->"]"
}

proc client'connfooter {chan nick ident addr} {
	puts stdout "Connection footers called for $nick $ident $::rhostnames($chan)"
	global hostnames dispnames idents servnick
	set can "$chan"
	set dispnames($can) $nick
	set idents($can) "user"
	if {$ident != ""} {set idents($can) $ident}
	set hostnames($can) $addr
	message'fd $chan $::config::me(server) [list "001" "$nick" "Welcome to the Internet Relay Network."]
	message'fd $chan $::config::me(server) [list "002" "$nick" "Your host is $::config::me(server), running version tclchatd0.1 IRC protocol version 2.7"]
	message'fd $chan $::config::me(server) [list "003" "$nick" "We never started. :P"]
	message'fd $chan $::config::me(server) [list "004" "$nick" "$::config::me(server) tclchatd0.1 ZSaoisw bimnlsptkheI beIklohv"]
	message'fd $chan $::config::me(server) [list "005" "$nick" "PREFIX=(ohv)@%+" "CHANMODES=beI,k,l,imnspt" "CHANTYPES=#&!+" "IDCHAN=!:5" "FNC" "are supported by this server"]
	set lusers [expr {int([array size ::dispnames]/2)+1}]
	message'fd $chan $::config::me(server) [list "251" "$nick" "$lusers" "0" "There are $lusers users and 0 invisible on 1 server"]
	message'fd $chan $::config::me(server) [list "375" "$nick" "- Begin MOTD"]
	foreach {lotd} $::config::me(motd) {
		message'fd $chan $::config::me(server) [list "372" "$nick" "- $lotd"]
	}
	message'fd $chan $::config::me(server) [list "376" "$nick" "- End of MOTD for $dispnames($chan)!$idents($chan)@$hostnames($chan)"]
	chan event $chan readable ""
	chan event $chan readable [list client'reg $chan $addr]
}

proc gset {k v} {
	uplevel "1" "set $k $v"
}

proc getss {chan} {
	return [string trim [chan gets $chan]]
}

proc client'unreg {chann addr} {
	global idents realnames conpass dispnames servers hostnames modes
	set msg [message'parse [getss $chann]]
	set chan "$chann"
	switch [string tolower [lindex $msg 0]] {
		"user" {
			if {[checknickname [lindex $msg 1]]} {set idents($chan) [lindex $msg 1]} {
			message'fd $chann $::config::me(server) [list "433" "*" [lindex $msg 1] "The ident you have chosen is erroneous. Pick another."]
			}
			set idents($chan) [lindex $msg 1]
			set realnames($chan) [lindex $msg 4]
			if {[info exists dispnames($chan)]} {
				client'connfooter $chann $dispnames($chan) [lindex $msg 1] $::hostnames($chan)
				chan event $chann readable [list client'reg $chan $addr]
			}
		}
		"pass" {
			set conpass($chan) [join [lrange $msg 1 end] " "]
			if {[lindex $msg 1] == "SERVICE"} {
				set approved 0
				foreach {k v} [array get ::config::services] {
					set pass [dict get $v pass]
					set host [dict get $v pass]
					set canchan 0
					set canchan [dict get $v canchan]
					if {
					([lindex $msg 2] == $k)
					&& ([lindex $msg 3] == $pass)
					&& ($addr == $host)
					} {
						set approved 1
						set hostnames($chan) [dict get $v spoof]
						set idents($chan) [dict get $v identspoof]
						if {$canchan} {append modes($chan) "S"}
						append modes($chan) "o"
					}
				}
				if {$approved} {
					message'fd $chan "$::config::me(server)" [list "NOTICE" "*" "You are now considered a Service. Please do not abuse your capabilities."]
				}
			}
		}
		"nick" {
			global idents realnames conpass dispnames
			if {[getfdbynick [lindex $msg 1]] != ""} {
				message'fd $chann $::config::me(server) [list "433" "*" [lindex $msg 1] "The nickname you have chosen is already in use. Pick another."]
			} {
				if {[checknickname [lindex $msg 1]]} {set dispnames($chan) [lindex $msg 1]} {
				message'fd $chann $::config::me(server) [list "433" "*" [lindex $msg 1] "The nickname you have chosen is erroneous. Pick another."]
				}
			}
			if {[info exists idents($chan)] && [info exists dispnames($chan)]} {
				client'connfooter $chann [lindex $msg 1] $idents($chan) $::hostnames($chan)
				chan event $chann readable [list client'reg $chan $addr]
			}
		}
	}
}

proc chan'names {chan room} {
	puts stdout "Names called $chan $room"
	foreach {nq} $::rooms($room) {
		set name [getnickbyfd $nq]
		set prefix ""
		#append namreply [getnickbyfd $nq]

		if {[info exists ::rooms(list,$room,v)]} { foreach {op} $::rooms(list,$room,v) {
			if {$op == $nq} {set prefix "+"}
		} }
		if {[info exists ::rooms(list,$room,h)]} { foreach {op} $::rooms(list,$room,h) {
			if {$op == $nq} {set prefix "%"}
		} }
		if {[info exists ::rooms(list,$room,o)]} { foreach {op} $::rooms(list,$room,o) {
			if {$op == $nq} {set prefix "@"}
			puts stdout "$prefix $nq"
		} }
		append namreply "$prefix"
		append namreply "$name "
		if {[string length $namreply] >= 372} {
			message'fd $chan $::config::me(server) [list "353" [getnickbyfd $chan] "@" $room $namreply]
		}
	}
	if {[string length $namreply] != 0} {message'fd $chan $::config::me(server) [list "353" [getnickbyfd $chan] "@" $room $namreply]}
	message'fd $chan $::config::me(server) [list "366" [getnickbyfd $chan] $room "End of /NAMES reply."]
}

proc hasmode {room mode} {
	foreach {mchar} [split $::rooms(mode,$room) {}] {
		if {$mchar == $mode} {return 1}
	}
	return 0
}

proc chan'adduser {fd room} {
	global rooms
	set canjoin 0
	set banned 0
	set newchan 0
	set chan $fd
	if {[info exists rooms($room)]} {if {[llength $rooms($room)] == 0} {
		set rooms($room) [list]
		set rooms(mode,$room) "nst"
		set canjoin 2
		set newchan 1
	} } {
		set rooms($room) [list]
		set rooms(mode,$room) "nst"
		set canjoin 2
		set newchan 1
	}
	if {[hasmode $room "i"]} {set canjoin 0}
	if {$canjoin != 2} {
		set canjoin 1
		if {[info exists ::rooms(list,$room,b)]} {
		foreach {banmask} $::rooms(list,$room,b) {
			if {[string match -nocase $banmask "$::dispnames($fd)!$::idents($fd)@$::hostnames($fd)"]} {
				set canjoin 0
				set banned 1
			}
		} }
		if {[info exists ::rooms(list,$room,e)]} {
		foreach {banmask} $::rooms(list,$room,e) {
			if {[string match -nocase $banmask "$::dispnames($fd)!$::idents($fd)@$::hostnames($fd)"]} {
				set canjoin 1
			}
		} }
		if {[info exists ::rooms(list,$room,e)]} {
		foreach {banmask} $::rooms(list,$room,I) {
			if {[string match -nocase $banmask "$::dispnames($fd)!$::idents($fd)@$::hostnames($fd)"]} {
				if {[hasmode $room "i"] && !$banned} {set canjoin 1}
			}
		} }
	}
	if {$canjoin == 0} {
		message\'fd $fd "-|-!-@$::config::me(server)" [list "474" [getnickbyfd $fd] $room "You cannot join $room (Banned: $banned, Modes: [chan'retmode $room]) "]
		return
	}
	if {[lsearch -exact rooms($room) $fd] != -1} {
		return
		# User is already on channel.
	}
	if {$newchan} {
		puts stdout "Channel created $room"
		set rooms(list,$room,o) [list $fd]
		set rooms(list,$room,h) [list]
		set rooms(list,$room,v) [list]
	}
	lappend rooms($room) $fd
	sendtochannoc $fd $room "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "JOIN" $room]
	message\'fdnoc $fd "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "JOIN" $room]
	chan'names $fd $room
	chan'topic $fd $room -
}

proc chan'canchgmode {src room state modeletter {param ""}} {
	if {[llength $::rooms($room)] == 0} {
		return 1
	}
	if {[string match "*S*" $::modes($src)]} {
		return 1
	}
	if {[info exists ::rooms(list,$room,o)]} {
		foreach {surce} $::rooms(list,$room,o) {
			if {$src == $surce} {return 1}
		}
	}
	if {[info exists ::rooms(list,$room,h)]} {
		foreach {surce} $::rooms(list,$room,h) {
			if {$src == $surce} {if {$modeletter !="o"} {return 1}}
		}
	}
	return 0
}

proc whois {fd nick {xtra "0"}} {
	if {!([getfdbynick $nick] == "")} {
		set fini [getfdbynick $nick]
		message'fd $fd "$::config::me(server)" [list "311" [getnickbyfd $fd] "$nick" "$::idents($fini)" "$::hostnames($fini)" "*" "$::realnames($fini)"]
		message'fd $fd "$::config::me(server)" [list "318" [getnickbyfd $fd] "$nick" "End of WHOIS list."]
	}
}

proc slappend {k v} {
	if {[info exists $k]} {uplevel "1" lappend $k $v} {uplevel "1" set $k [list $v]}
}

proc sappend {k v} {
	if {[info exists $k]} {uplevel "1" append $k $v} {uplevel "1" set $k $v}
}

proc chan'topic {src room {topic "-"}} {
	global rooms
	if {"-"==$topic} {
		if {[info exists rooms(topic,$room)]} {set m 332;set t $rooms(topic,$room)} {set m 331;set t "No topic is set."}
		message'fd $src "$::config::me(server)" [list $m [getnickbyfd $src] $room $t]
	} {
		if {[hasmode $room t]} {
			set cantopic [chan'canchgmode $src $room + "t" ""]
		} {
			set cantopic 1
		}
		if {$cantopic} {
			set rooms(topic,$room) $topic
			sendtochan "none" $room "$::dispnames($src)!$::idents($src)@$::hostnames($src)" [list "TOPIC" $room $topic]
		}
	}
}

proc chan'chgmode {src room state modeletter param} {
	global rooms
	set lst 0
	switch $modeletter {
		o {set lst 728}
		h {set lst 728}
		v {set lst 728}
		b {set lst 367}
		e {set lst 346}
		I {set lst 348}
	}
	if {$lst != 0 && ""==$param} {
		if {![info exists ::rooms(list,$room,$modeletter)]} {set ::rooms(list,$room,$modeletter) [list]}
		foreach {prm} $::rooms(list,$room,$modeletter) {
			if {$lst > 500} {
				message'fd $src "$::config::me(server)" [list "$lst" [getnickbyfd $src] "$room" $modeletter [getnickbyfd $prm]]
			} {
				message'fd $src "$::config::me(server)" [list "$lst" [getnickbyfd $src] "$room" $prm]
			}
		}
		if {$lst > 500} {
			message'fd $src "$::config::me(server)" [list "[expr {$lst+1}]" [getnickbyfd $src] "$room" $modeletter "End of +$modeletter list."]
		} {
			message'fd $src "$::config::me(server)" [list "[expr {$lst+1}]" [getnickbyfd $src] "$room" "End of +$modeletter list."]
		}
		return
	}
	if {[chan'canchgmode $src $room $state $modeletter $param]} {
		if {$lst > 100 && [string length $param] && ($state == "+")} {
			if {$lst > 500} {set parm [getfdbynick $param]} {set parm $param}
			lappend rooms(list,$room,$modeletter) $parm
		}
		if {$lst > 100 && [string length $param] && ($state == "-")} {
			if {$lst > 500} {set parm [getfdbynick $param]} {set parm $param}
			set rooms(list,$room,$modeletter) [lreplace $rooms(list,$room,$modeletter) [lsearch -exact $rooms(list,$room,$modeletter) $parm] [lsearch -exact $rooms(list,$room,$modeletter) $parm]]
		}
		if {!$lst && ($state == "+")} {append rooms(mode,$room) $modeletter}
		if {!$lst && ($state == "-")} {set rooms(mode,$room) [string map [list $modeletter ""] $rooms(mode,$room)]}
		set mch $state
		append mch $modeletter
		sendtochannoc $src $room "$::dispnames($src)!$::idents($src)@$::hostnames($src)" [list "MODE" $room $mch $param]
		message'fdnoc $src "$::dispnames($src)!$::idents($src)@$::hostnames($src)" [list "MODE" $room $mch $param]
	}
}

proc chan'retmode {room} {
	if {[info exists ::rooms(mode,$room)]} {
		return $::rooms(mode,$room)
	}
	return ""
}

proc client'reg {chan addr} {
	global rooms modes aways
	set msg [message'parse [getss $chan]]
	switch [string tolower [lindex $msg 0]] {
		"privmsg" {
			if {[getfdbynick [lindex $msg 1]] != ""} {
				message'send [lindex $msg 1] "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "PRIVMSG" [lindex $msg 1] [lindex $msg 2]]
				if {$aways([getfdbynick [lindex $msg 1]])!=""} {
					message'fd $chan $::config::me(server) [list "301" $::dispnames($chan) [lindex $msg 1] $aways([getfdbynick [lindex $msg 1]])
				}
			} {
				foreach {chn} [split [lindex $msg 1] ","] {
					sendtochan $chan $chn "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "PRIVMSG" $chn [lindex $msg 2]]
				}
			}
		}

		"away" {
			set aways($chan) [lindex $msg 1]
		}

		"notice" {
			if {[getfdbynick [lindex $msg 1]] != ""} {
				message'send [lindex $msg 1] "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "NOTICE" [lindex $msg 1] [lindex $msg 2]]
				if {$aways([getfdbynick [lindex $msg 1]])!=""} {
					message'fd $chan $::config::me(server) [list "301" $::dispnames($chan) [lindex $msg 1] $aways([getfdbynick [lindex $msg 1]])
				}
			} {
				foreach {chn} [split [lindex $msg 1] ","] {
					sendtochan $chan $chn "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "NOTICE" $chn [lindex $msg 2]]
				}
			}
		}

		"names" {
			if {[lindex $msg 1] != ""} {chan'names $chan [lindex $msg 1]}
		}

		"ping" {
			message'fd $chan $::config::me(server) [list "PONG" $::config::me(server) [lindex $msg 1]]
		}

		"whois" {
			if {[lindex $msg 1] != ""} {whois $chan [lindex $msg 1] 0}
		}

		"who" {
			foreach {niq} $rooms([lindex $msg 1]) {
				if {$::aways($niq) == ""} {
					set hg "H"
				} {
					set hg "G"
				}
				message'fd $chan $::config::me(server) [list "352" "*" [lindex $msg 1] $::idents($niq) $::hostnames($niq) $::config::me(server) $::dispnames($niq) $hg "1 $::realnames($niq)"]
			}
			message'fd $chan $::config::me(server) [list "315" [lindex $msg 1] "End of /WHO"]
		}

		"mode" {
			foreach {chn} [split [lindex $msg 1] ","] {
				set okchan 0
				switch [string index $chn 0] {
					"#" {set okchan 1}
					"&" {set okchan 1}
					"!" {set okchan 1}
					"+" {set okchan 1}
				}
				if {$okchan && [lindex $msg 2]!="" && [lindex $msg 2]!=":" && [lindex $msg 2]!=" " } {
					set state +
					set ctr 1
					foreach {l} [split [lindex $msg 2] {}] {
						if {$l == "+"} {set state +; continue}
						if {$l == "-"} {set state -; continue}
						switch -regexp $l {
							"[ohvbeI]" {chan'chgmode $chan $chn $state $l [lindex $msg [expr {1+[incr ctr]}]]}
							"[imnsptrSCN]" {chan'chgmode $chan $chn $state $l ""}
						}
					}
				} {
					message'fd $chan $::config::me(server) [list "324" "*" $chn "+[chan'retmode $chn]"]
				}
			}
		}

		"topic" {
			if {""==[lindex $msg 1]} continue
			foreach {chn} [split [lindex $msg 1] ","] {
				set okchan 0
				switch [string index $chn 0] {
					"#" {set okchan 1}
					"&" {set okchan 1}
					"!" {set okchan 1;set $chn "!AAAAA[string range $chn 1 end]"}
					"+" {set okchan 1}
				}
				if {$okchan} {
					chan'topic $chan $chn [lindex $msg 2]
				}
			}
		}

		"join" {
			foreach {chn} [split [lindex $msg 1] ","] {
				set okchan 0
				switch [string index $chn 0] {
					"#" {set okchan 1}
					"&" {set okchan 1}
					"!" {set okchan 1;set $chn "!AAAAA[string range $chn 1 end]"}
					"+" {set okchan 1}
				}
				if {$okchan} {
					chan'adduser $chan $chn
				}
			}
		}

		"oper" {
			set approved 0
			foreach {k v} [array get ::config::services] {
				set pass [dict get $v pass]
				set host [dict get $v host]
				if {
				([lindex $msg 1] == $k)
				&& ([lindex $msg 2] == $pass)
				&& ($::rhostnames($chan) == $host)
				} {
					set approved 1
					set hostnames($chan) [dict get $v spoof]
					set idents($chan) [dict get $v identspoof]
					append modes($chan) "S"
					append modes($chan) "o"
				}
			}
			if {$approved} {
				message'fd $chan "$::config::me(server)" [list "NOTICE" $::dispnames($chan) "You are now considered an Oper. Please do not abuse your capabilities."]
			}
		}

		"nick" {
			chgnick $chan [lindex $msg 1]
		}

		"quit" {
			client'err $chan "$::idents($chan)@$::hostnames($chan)" "$::dispnames($chan)" "Quit: [lindex $msg 1]"
		}

		"part"	{
			foreach {chn} [split [lindex $msg 1] ","] {
				set rooms($chn) [lreplace $rooms($chn) [lsearch -exact $rooms($chn) $chan] [lsearch -exact $rooms($chn) $chan]]
				set rooms(list,$chn,o) [lreplace $rooms(list,$chn,o) [lsearch -exact $rooms(list,$chn,o) $chan] [lsearch -exact $rooms(list,$chn,o) $chan]]
				set rooms(list,$chn,h) [lreplace $rooms(list,$chn,h) [lsearch -exact $rooms(list,$chn,h) $chan] [lsearch -exact $rooms(list,$chn,h) $chan]]
				set rooms(list,$chn,v) [lreplace $rooms(list,$chn,v) [lsearch -exact $rooms(list,$chn,v) $chan] [lsearch -exact $rooms(list,$chn,v) $chan]]
				sendtochan $chan $chn "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "PART" $chn "Part: [lindex $msg 2]"]
				message'fd $chan "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "PART" $chn "Part: [lindex $msg 2]"]
			}
		}

		"kick"	{
			set zhan [getfdbynick [lindex $msg 2]]
			foreach {chn} [split [lindex $msg 1] ","] {
				if {![chan'canchgmode $chan $chn "+" "h"]} {continue}
				if {![chan'canchgmode $chan $chn "+" "o"] && [chan'canchgmode $zhan $chn "+" "o"]} {continue}
				set rooms($chn) [lreplace $rooms($chn) [lsearch -exact $rooms($chn) $zhan] [lsearch -exact $rooms($chn) $zhan]]
				set rooms(list,$chn,o) [lreplace $rooms(list,$chn,o) [lsearch -exact $rooms(list,$chn,o) $zhan] [lsearch -exact $rooms(list,$chn,o) $zhan]]
				set rooms(list,$chn,h) [lreplace $rooms(list,$chn,h) [lsearch -exact $rooms(list,$chn,h) $zhan] [lsearch -exact $rooms(list,$chn,h) $zhan]]
				set rooms(list,$chn,v) [lreplace $rooms(list,$chn,v) [lsearch -exact $rooms(list,$chn,v) $zhan] [lsearch -exact $rooms(list,$chn,v) $zhan]]
				sendtochan $chan $chn "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "KICK" $chn [lindex $msg 2] [lindex $msg 3]]
				message'fd $chan "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "KICK" $chn [lindex $msg 2] [lindex $msg 3]]
				message'fd $zhan "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "KICK" $chn [lindex $msg 2] [lindex $msg 3]]
			}
		}
	}
	if {[string match "*o*" $modes($chan)]} {
	switch -nocase [lindex $msg 0] {
		"kill" {
			set killed [getfdbynick [lindex $msg 1]]
			client'err $killed "$::idents($killed)@$::hostnames($killed)" "$::dispnames($killed)" "Killed ($::dispnames($chan) ([lindex $msg 2]))"
		}
		"sethost" {
			global hostnames
			if {""==[lindex $msg 1]} {
				message'fd $chan $::config::me(server) [list "NOTICE" [getnickbyfd $chan] "You need to specify a host to change to"]
			}
			sendtoneighbut $chan "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "QUIT" "/CHGHOST or /SETHOST used; cycling"]
			set hostnames($chan) [lindex $msg 1]
			sendtoneighchan $chan "$::dispnames($chan)!$::idents($chan)@$::hostnames($chan)" [list "JOIN" "%chan"]
		}
		"chghost" {
			global hostnames
			if {""==[lindex $msg 1]} {
				message'fd $chan $::config::me(server) [list "NOTICE" [getnickbyfd $chan] "You need to specify a user to change host of"]
			}
			if {""==[lindex $msg 2]} {
				message'fd $chan $::config::me(server) [list "NOTICE" [getnickbyfd $chan] "You need to specify a host to change to"]
			}
			set zhan [getfdbynick [lindex $msg 1]]
			sendtoneighbut $zhan "$::dispnames($zhan)!$::idents($zhan)@$::hostnames($zhan)" [list "QUIT" "/CHGHOST or /SETHOST used; cycling"]
			set hostnames($zhan) [lindex $msg 2]
			sendtoneighchan $zhan "$::dispnames($zhan)!$::idents($zhan)@$::hostnames($zhan)" [list "JOIN" "%chan"]
		}
	}
	}
}

proc sendtochan {sf room src zarg} {
	if {![info exists ::rooms($room)]} {return}
	foreach {nq} $::rooms($room) {
		if {$nq != $sf} {message'fd $nq "$src" $zarg}
	}
}

proc sendtochannoc {sf room src zarg} {
	if {![info exists ::rooms($room)]} {return}
	foreach {nq} $::rooms($room) {
		if {$nq != $sf} {message'fdnoc $nq "$src" $zarg}
	}
}

proc client'err {chan addr nick reason} {
	global rooms
	chan puts $chan ":$::config::me(server) ERROR :Closing link: $nick\[$addr\] ($reason)"
	chan close $chan
	client'eoc $chan "$reason"
	foreach {room nqls} [array get ::rooms] {
		if {[lsearch -exact $nqls $chan] != -1} {set rooms($room) [lreplace $nqls [lsearch -exact $nqls $chan] [lsearch -exact $nqls $chan]]}
		if {[lsearch -exact $nqls $chan] != -1} {set rooms(list,$room,o) [lreplace $rooms(list,$room,o) [lsearch -exact $rooms(list,$room,o) $chan] [lsearch -exact $rooms(list,$room,o) $chan]]}
		if {[lsearch -exact $nqls $chan] != -1} {set rooms(list,$room,h) [lreplace $rooms(list,$room,h) [lsearch -exact $rooms(list,$room,h) $chan] [lsearch -exact $rooms(list,$room,h) $chan]]}
		if {[lsearch -exact $nqls $chan] != -1} {set rooms(list,$room,v) [lreplace $rooms(list,$room,v) [lsearch -exact $rooms(list,$room,v) $chan] [lsearch -exact $rooms(list,$room,v) $chan]]}
	}
}

proc client'eoc {chan reason} {
	global rooms dispnames realnames idents hostnames
	set dn $dispnames($chan)
	set dispnames($chan) ""
	sendtoneighbut $chan "${dn}!$::idents($chan)@$::hostnames($chan)" [list "QUIT" "$reason"]
	unset realnames($chan)
	unset idents($chan)
	unset hostnames($chan)
}

proc message'send {nick src zarg} {
	set wrt ":$src"
	append wrt " [join [lrange $zarg 0 end-1] " "]"
	append wrt " :[lindex $zarg end]"
	chan puts [getfdbynick $nick] "$wrt"
}

proc message'fd {nick src zarg} {
	set wrt ":$src"
	append wrt " [join [lrange $zarg 0 end-1] " "]"
	append wrt " :[lindex $zarg end]"
	chan puts $nick "$wrt"
}

proc message'fdnoc {nick src zarg} {
	set wrt ":$src"
	append wrt " [join [lrange $zarg 0 end-1] " "]"
	append wrt " [lindex $zarg end]"
	chan puts $nick "$wrt"
}

proc stricmp {str1 str2} {
	if {[string match -nocase "${str2}" $str1]} {return 1} {return 0}
}

proc message'parse {message} {
	if {[string index $message 0] == ":"} {
		set one 1
		set two 2
	} {
		set one 0
		set two 1
	}
	set splits [split $message ":"]
	set payload [join [lrange $splits $two end] ":"]
	set comd [split [string trim [lindex $splits $one]] " "]
	lappend comd "$payload"
	return $comd
}

foreach {pblock} $::config::listen(port) {
	socket -server accept -myaddr [lindex $pblock 0] [lindex $pblock 1]
}

foreach {pblock} $::config::listen(sslport) {
	::tls::socket -tls1 1 -ssl2 0 -certfile ircd.pem -server accept-ssl -myaddr [lindex $pblock 0] [lindex $pblock 1]
}

vwait forever
