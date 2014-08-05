#!/usr/bin/env tclsh8.6

# TCL Chatd
# Inspired by RONSOR's chat daemon

# Obviously we require tcllib.
package require md5
package require tls
package require sqlite3
package require dns
set opmodes "qaohv"

if {[catch {dict get {}} zun]} {source dict.tcl}

sqlite3 ircdb ./irc.db
ircdb eval {CREATE TABLE IF NOT EXISTS logins (uname text, pass text)}

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
array set extinfo {}
array set pings {}

namespace eval config {
	array set me {}
	array set listen {}
	array set servers {}
	array set services {}
}

source ircd.conf
#source s2s.tcl
set prefixls ""

append prefixls [set opprefix(q) "$::config::me(qprefix)"]
append prefixls [set opprefix(a) "$::config::me(aprefix)"]
append prefixls [set opprefix(o) "$::config::me(oprefix)"]
append prefixls [set opprefix(h) "$::config::me(hprefix)"]
append prefixls [set opprefix(v) "$::config::me(vprefix)"]

proc login {fd user pass} {
	set pq [::md5::md5 -hex $pass]
	set zeb [ircdb eval {SELECT }]
}

proc getfdbynick {nick} {
	foreach {fdp nic} [array get ::dispnames] {
		if {[string tolower $nick] == [string tolower $nic]} {
			return $fdp
		}
	}
	return
}

proc getnickbyfd {nick} {
	foreach {fdp nic} [array get ::dispnames] {
		if {$nick == $fdp} {
			return $nic
		}
	}
}

proc rand {minn maxx} {
	set maxnum [expr {$maxx - $minn}]
	set fp [open /dev/urandom r]
	set bytes [read $fp 6]
	close $fp
	scan $bytes %c%c%c%c%c%c ca co ce cu ci ch
	set co [expr {$co + (2 ** 8)}]
	set ce [expr {$ce + (2 ** 16)}]
	set cu [expr {$cu + (2 ** 24)}]
	set ci [expr {$ci + (2 ** 32)}]
	set ch [expr {$ch + (2 ** 40)}]
	return [expr {$minn+(($ca+$co+$ce+$cu+$ci+$ch)%$maxnum)}]
}

proc makessl {fd} {
	global modes
	append modes($fd) "Z"
}

proc accept {chan addr port} {
	global hostnames dispnames idents realnames modes rhostnames aways extinfo
	dict set extinfo($chan) exists 1
	set modes($chan) ""
	set idents($chan) ""
	set dispnames($chan) ""
	set realnames($chan) ""
	set rhostnames($chan) "$addr"
	set aways($chan) ""
	set ctr 0
	set xddr [string match "*:*" $addr]
	if {$xddr} {
		set wddr ":"
		set dnslen 1
	} {
		set dnslen 0
		set wddr "."
	}
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
	append modes($chan) "x"
	append zddr "IP"
	set hostnames($chan) $zddr
	fconfigure $chan -buffering line -blocking 0
	putss $chan ":$::config::me(server) 020 * :$::config::me(welcome)"
	fileevent $chan readable [list client'unreg $chan $addr]
}

proc gethostname {chan} {
	if {[string match "*x*" $::modes($chan)]} {
		return $::hostnames($chan)
	} {
		return $::rhostnames($chan)
	}
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
	fconfigure $chan -buffering line -blocking 1
	::tls::handshake $chan
	fconfigure $chan -buffering line -blocking 0
	append modes($chan) "x"

	putss $chan ":$::config::me(server) 020 * :$::config::me(welcome)"
	fileevent $chan readable [list client'unreg $chan $addr]
}

proc checknickname {nick} {
	set good "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]{}~/\|-_^()"
	set fishy "~-"
	if {[string is digit [string index $nick 0]]} {
		return 0
	}
	foreach {char} [split $fishy {}] {
		if {[string match "${char}*" $nick]} {return 0}
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
		return
	}
	if {[getfdbynick $nick] != ""} {
		message'fd $chan $::config::me(server) [list "433" "$::dispnames($chan)" "$nick" "The nickname you have chosen is already in use. Pick another."]
	} {
		sendtoneigh $chan "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "NICK" "$nick"]
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
	putss stdout "[join $sendto "->"]"
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
	putss stdout "[join $sendto "->"]"
}

proc retneighchan {chan} {
	global rooms
	set sendto [list]
	#message'fd $chan $src $zarg
	foreach {room} [array names rooms] {
		if {[lsearch -exact $rooms($room) "$chan"] == -1} {continue}
		if {[string match "list,*" $room]} {continue}
		append sendto " $room"
	}
	return $sendto
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
	putss stdout "[join $sendto "->"]"
}

proc pingout {chan} {
	global pings
	if {![info exists ::hostnames($chan)]} {
		return
	}
	if {!$pings($chan)} {
		client'err $chan "$::hostnames($chan)" "$::dispnames($chan)" "Ping timeout: 80 seconds"
	}
	putss $chan "PING $::config::me(server)"
	set pings($chan) 0
	after 80000 pingout $chan
}

proc client'connfooter {chan nick ident addr} {
	putss stdout "Connection footers called for $nick $ident $::rhostnames($chan)"
	global hostnames dispnames idents servnick pings
	if {""==$nick} {
		fileevent $chan readable [list client'unreg $chan $addr]
		return
	}
	set pings($chan) 1
	pingout $chan
	set can "$chan"
	set dispnames($can) $nick
	set idents($can) $nick
	if {$ident != ""} {set idents($can) $ident}
	set hostnames($can) $addr
	message'fd $chan $::config::me(server) [list "001" "$nick" "Welcome to the Internet Relay Network."]
	message'fd $chan $::config::me(server) [list "002" "$nick" "Your host is $::config::me(server), running version tclchatd0.1 IRC protocol version 2.7"]
	message'fd $chan $::config::me(server) [list "003" "$nick" "We never started. :P"]
	message'fd $chan $::config::me(server) [list "004" "$nick" "$::config::me(server) tclchatd0.1 ZSaoisw bimnlsptkoOHVheIz beIklohvOHVz"]
	message'fd $chan $::config::me(server) [list "005" "$nick" "PREFIX=($::opmodes)$::prefixls" "CHANMODES=QAzbeIOHV,k,l,imnspt" "CHANTYPES=#&!+" "IDCHAN=!:5" "FNC" "are supported by this server"]
	set lusers [expr {int([array size ::dispnames]/2)+1}]
	message'fd $chan $::config::me(server) [list "251" "$nick" "$lusers" "0" "There are $lusers users and 0 invisible on 1 server"]
	message'fd $chan $::config::me(server) [list "375" "$nick" "Begin MOTD"]
	foreach {lotd} $::config::me(motd) {
		message'fd $chan $::config::me(server) [list "372" "$nick" "- $lotd"]
	}
	message'fd $chan $::config::me(server) [list "376" "$nick" "End of MOTD for $dispnames($chan)!$idents($chan)@[gethostname $chan]"]
	fileevent $chan readable ""
	fileevent $chan readable [list client'reg $chan $addr]
	#server'introducecli $chan $::config::me(server)
	sendtoallumode o $::config::me(server) [list "NOTICE" "*" "CONN $dispnames($chan)!$idents($chan)@[gethostname $chan] $::rhostnames($chan)"]
}

proc client'srvconnfooter {srv chan nick ident addr} {
	global hostnames dispnames idents servnick
	if {""==$nick} {
		fileevent $chan readable [list client'unreg $chan $addr]
		return
	}
	set can "$chan"
	set dispnames($can) $nick
	set idents($can) $nick
	if {$ident != ""} {set idents($can) $ident}
	set hostnames($can) $addr
	#server'introducecli $chan $::config::me(server)
	putss stdout "Connection footers called for $nick $ident $::rhostnames($chan) on $srv"
	sendtoallumode o $::config::me(server) [list "NOTICE" "*" "CONN $dispnames($chan)!$idents($chan)@[gethostname $chan] $::rhostnames($chan)"]
}

proc gset {k v} {
	uplevel "1" "set $k $v"
}

proc getss {chan} {
	return [string trim [gets $chan]]
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
				fileevent $chann readable [list client'reg $chan $addr]
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
			set go 1
			client`unreg`nick $chan $msg
		}

	}
}

proc client`randnick {chan} {
	global dispnames
	set rn [rand 100000 999999]
	if {[getfdbynick "U$rn"] != ""} {
		client`randnick $chan
	} {
		client'connfooter $chan "U$rn" $::idents($chan) $::hostnames($chan)
	}
}

proc client`unreg`nick {chan msg} {
	global dispnames idents
	if {[getfdbynick [lindex $msg 1]] != ""} {
		message'fd $chan $::config::me(server) [list "433" "*" [lindex $msg 1] "The nickname you have chosen is already in use. Forcing nick change to a random nick."]
		return
		client`randnick $chan
	}
	if {[lindex $msg 1] == ""} {
		message'fd $chan $::config::me(server) [list "433" "*" [lindex $msg 1] "The nickname you have chosen is already in use. Pick another."]
		return
	}
	if {[getfdbynick [lindex $msg 1]] == ""} {
		if {[checknickname [lindex $msg 1]]} {
			set dispnames($chan) [lindex $msg 1]
			client'connfooter $chan [lindex $msg 1] $idents($chan) $::hostnames($chan)
		} {
			message'fd $chan $::config::me(server) [list "433" "*" [lindex $msg 1] "The nickname you have chosen is erroneous. Pick another."]
			set go 0
		}
	}
}

proc chan'names {chan room} {
	putss stdout "Names called $chan $room"
	foreach {nq} $::rooms($room) {
		set name [getnickbyfd $nq]
		set prefix ""
		#append namreply [getnickbyfd $nq]

		if {[info exists ::rooms(list,$room,v)]} { foreach {op} $::rooms(list,$room,v) {
			if {$op == $nq} {set prefix $::opprefix(v)}
		} }
		if {[info exists ::rooms(list,$room,h)]} { foreach {op} $::rooms(list,$room,h) {
			if {$op == $nq} {set prefix $::opprefix(h)}
		} }
		if {[info exists ::rooms(list,$room,o)]} { foreach {op} $::rooms(list,$room,o) {
			if {$op == $nq} {set prefix $::opprefix(o)}
			putss stdout "$prefix $nq"
		} }
		if {[info exists ::rooms(list,$room,a)]} { foreach {op} $::rooms(list,$room,a) {
			if {$op == $nq} {set prefix $::opprefix(a)}
		} }
		if {[info exists ::rooms(list,$room,q)]} { foreach {op} $::rooms(list,$room,q) {
			if {$op == $nq} {set prefix $::opprefix(q)}
		} }
		append namreply "$prefix"
		append namreply "$name "
		if {[string length $namreply] >= 372} {
			message'fd $chan $::config::me(server) [list "353" [getnickbyfd $chan] "=" $room $namreply]
		}
	}
	if {[string length $namreply] != 0} {message'fd $chan $::config::me(server) [list "353" [getnickbyfd $chan] "@" $room $namreply]}
	message'fd $chan $::config::me(server) [list "366" [getnickbyfd $chan] $room "End of /NAMES reply."]
}



proc hasmode {room mode} {
	foreach {mchar} [split [chan'retmode $room] {}] {
		if {$mchar == $mode} {return 1}
	}
	return 0
}

proc chan'adduser {fd room {apass ""}} {
	global rooms
	set canjoin 1
	set banned 0
	set newchan 0
	set mods ""
	set chan $fd
	if {![hasmode $room "r"]} {if {[info exists rooms($room)]} {if {[llength $rooms($room)] == 0} {
		set rooms($room) [list]
		set rooms(mode,$room) "nt"
		set canjoin 2
		set newchan 1
	} } {
		set rooms($room) [list]
		set rooms(mode,$room) "nt"
		set canjoin 2
		set newchan 1
	} }
	if {[hasmode $room "i"]} {set canjoin 0}
	if {$canjoin != 2} {
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
		if {[info exists ::rooms(list,$room,I)]} {
		foreach {banmask} $::rooms(list,$room,I) {
			if {[string match -nocase $banmask "$::dispnames($fd)!$::idents($fd)@$::hostnames($fd)"]} {
				if {[hasmode $room "i"] && !$banned} {set canjoin 1}
			}
		} }
		if {$apass == ""} {set zzzzzzzzzzzzzzzzzzzzzzz z} {
		if {[info exists ::rooms(list,$room,Q)]} {
		foreach {banmask} $::rooms(list,$room,Q) {
			if {$banmask == $apass} {
				if {!$banned} {set canjoin 1
				lappend rooms(list,$room,q) "$fd"
				append mods q}
			}
		} }
		if {[info exists ::rooms(list,$room,A)]} {
		foreach {banmask} $::rooms(list,$room,A) {
			if {$banmask == $apass} {
				if {!$banned} {set canjoin 1
				lappend rooms(list,$room,a) "$fd"
				append mods a}
			}
		} }
		if {[info exists ::rooms(list,$room,O)]} {
		foreach {banmask} $::rooms(list,$room,O) {
			if {$banmask == $apass} {
				if {!$banned} {set canjoin 1
				lappend rooms(list,$room,o) "$fd"
				append mods o}
			}
		} }
		if {[info exists ::rooms(list,$room,H)]} {
		foreach {banmask} $::rooms(list,$room,H) {
			if {$banmask == $apass} {
				if {!$banned} {set canjoin 1;lappend rooms(list,$room,h) "$fd";append mods h}
			}
		} }
		if {[info exists ::rooms(list,$room,V)]} {
		foreach {banmask} $::rooms(list,$room,V) {
			if {$banmask == $apass} {
				if {!$banned} {set canjoin 1;lappend rooms(list,$room,v) "$fd";append mods v}
			}
		} }
		}
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
		putss stdout "Channel created or apassed $room"
		#set rooms($room) [list $fd]
		set rooms(list,$room,q) [list $fd]
		set rooms(list,$room,a) [list]
		set rooms(list,$room,o) [list $fd]
		set rooms(list,$room,h) [list]
		set rooms(list,$room,v) [list]
	}

	lappend rooms($room) $fd
	sendtochannoc $fd $room "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "JOIN" $room]
	message\'fdnoc $fd "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "JOIN" $room]
	set modus [list "MODE" $room "+$mods"]
	for {set x 0} {$x<[string length $mods]} {incr x} {lappend modus [getnickbyfd $fd]}
	if {""!=$mods} {sendtochannoc $fd $room "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" $modus}
	chan'names $fd $room
	chan'topic $fd $room -
}


proc chan'ls {src} {
	foreach {room lusers} [array get ::rooms] {
		if {[hasmode $room "s"]} {continue}
		if {[string match "*,*" $room]} {continue}
		if {[info exists rooms(topic,$room)]} {set m 332;set t $rooms(topic,$room)} {set m 331;set t " "}
		message'fd $src "$::config::me(server)" [list "322" [getnickbyfd $src] $room [llength $lusers] $t]
	}
	message'fd $src "$::config::me(server)" [list "323" [getnickbyfd $src] "End of /LIST reply."]
}

proc chan'canchgmode {src room state modeletter {param ""}} {
	if {[llength $::rooms($room)] == 0} {
		return 1
	}
	if {[string match "*S*" $::modes($src)]} {
		return 1
	}
	if {[info exists ::rooms(list,$room,q)]} {
		foreach {surce} $::rooms(list,$room,q) {
			if {$src == $surce} {return 1}
		}
	}
	if {[info exists ::rooms(list,$room,a)]} {
		foreach {surce} $::rooms(list,$room,a) {
			if {$src == $surce} {
				if {$modeletter !="q" && $modeletter !="Q"} {
					return 1
				}
			}
		}
	}
	if {[info exists ::rooms(list,$room,o)]} {
		foreach {surce} $::rooms(list,$room,o) {
			if {$src == $surce} {
				if {$modeletter !="q" && $modeletter !="a" && $modeletter !="Q" && $modeletter !="A" } {
					return 1
				}
			}
		}
	}
	if {[info exists ::rooms(list,$room,h)]} {
		foreach {surce} $::rooms(list,$room,h) {
			if {$src == $surce} {
				if {$modeletter !="o" && $modeletter !="O"} {
					return 1
				}
			}
		}
	}
	return 0
}


proc whois {fd nick {xtra "0"}} {
	if {!([getfdbynick $nick] == "")} {
		set fini [getfdbynick $nick]
		message'fd $fd "$::config::me(server)" [list "311" [getnickbyfd $fd] "$nick" "$::idents($fini)" "$::hostnames($fini)" "*" "$::realnames($fini)"]
		#message'fd $fd "$::config::me(server)" [list "319" [getnickbyfd $fd] "$nick" "Cannot show due to TCL error. :P"]
		if {[info exists ::extinfo($fini)]} {
			foreach {k v} $::extinfo($fini) {
				if {$k=="umetadata"} {
					foreach {x w} $v {message'fd $fd "$::config::me(server)" [list "309" [getnickbyfd $fd] "$nick" "Metadata: $x = $w"]}
				}
				if {$k=="account"} {
					message'fd $fd "$::config::me(server)" [list "330" [getnickbyfd $fd] "$nick" "$v" "is authed as"]
				}
			}
		}
		if {$xtra} {message'fd $fd "$::config::me(server)" [list "378" [getnickbyfd $fd] "$nick" "is connecting from *@$::rhostnames($fini) $::rhostnames($fini)"]}
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

			if {![chan'canchgmode $src $room + "t" ""] && ([is_maskmode $room b $src] || [is_maskmode $room z $src])} { set cantopic 0 } { set cantopic 1 }
			putss stdout "if this is executed, wrang."
		}
		if {$cantopic} {
			set rooms(topic,$room) $topic
			sendtochan $src $room "$::dispnames($src)!$::idents($src)@$::hostnames($src)" [list "TOPIC" $room $topic]
			message'fd $src "$::dispnames($src)!$::idents($src)@$::hostnames($src)" [list "TOPIC" $room $topic]
		}
	}
}

proc chan'chgmode {src room state modeletter param} {
	global rooms
	set lst 0
	set oponly 0
	switch $modeletter {
		q {set lst 728}
		a {set lst 728}
		o {set lst 728}
		h {set lst 728}
		v {set lst 728}
		b {set lst 367}
		e {set lst 346}
		I {set lst 348}
		z {set lst 367}
		Q {set lst 1728;set oponly 1}
		A {set lst 1728;set oponly 1}
		O {set lst 1728;set oponly 1}
		H {set lst 1728;set oponly 1}
		V {set lst 1728;set oponly 1}
	}
	if {$lst != 0 && ""==$param} {
		if {![info exists ::rooms(list,$room,$modeletter)]} {set ::rooms(list,$room,$modeletter) [list]}
		foreach {prm} $::rooms(list,$room,$modeletter) {
			if {$lst == 728 || ($lst == 1728) && (!$oponly || [chan'canchgmode $src $room $state $modeletter $param])} {
				if {$lst == 1728} {set lst 728} {set prm [getnickbyfd $prm]}
				if {$oponly} {break}
				message'fd $src "$::config::me(server)" [list "$lst" [getnickbyfd $src] "$room" $modeletter $prm]
			} {
				message'fd $src "$::config::me(server)" [list "$lst" [getnickbyfd $src] "$room" $prm]
			}
		}
		if {$lst > 500} {
			if {$lst > 1000} {set lst [expr {$lst - 1000}]}
			message'fd $src "$::config::me(server)" [list "[expr {$lst+1}]" [getnickbyfd $src] "$room" $modeletter "End of +$modeletter list."]
		} {
			message'fd $src "$::config::me(server)" [list "[expr {$lst+1}]" [getnickbyfd $src] "$room" "End of +$modeletter list."]
		}
		return
	}
	if {[chan'canchgmode $src $room $state $modeletter $param]} {
		if {$lst > 100 && [string length $param] && ($state == "+")} {
			if {$lst == 728} {set parm [getfdbynick $param]} {set parm $param}
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
		if {$oponly} {
			sendtochannoc $src "list,$room,q" "$::dispnames($src)!$::idents($src)@$::hostnames($src)" [list "MODE" $room $mch $param]
			sendtochannoc $src $room "$::dispnames($src)!$::idents($src)@$::hostnames($src)" [list "MODE" $room $mch "*"]
		} {
			sendtochannoc $src $room "$::dispnames($src)!$::idents($src)@$::hostnames($src)" [list "MODE" $room $mch $param]
		}
		message'fdnoc $src "$::dispnames($src)!$::idents($src)@$::hostnames($src)" [list "MODE" $room $mch $param]
	}
}

proc sendtoallumode {mode src zarg} {
	foreach {k v} [array get ::modes] {
		if {![string match "*${mode}*" $v]} {continue}
		message'fd $k $src $zarg
	}
}

proc chan'retmode {room} {
	if {[info exists ::rooms(mode,$room)]} {
		return $::rooms(mode,$room)
	}
	return ""
}

proc client'reg {chan addr} {
	set msg [message'parse [getss $chan]]
	client'rreg $chan $msg
}

proc sendtobutserv {but msg} {
	
}

proc client'rreg {chan msg} {
	global rooms modes aways pings extinfo
	if {![string match "*L*" $modes($chan)]} {
	switch [string tolower [lindex $msg 0]] {
		"privmsg" {
			if {[getfdbynick [lindex $msg 1]] != ""} {
				message'send [lindex $msg 1] "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "PRIVMSG" [lindex $msg 1] [lindex $msg 2]]
				if {$aways([getfdbynick [lindex $msg 1]])!=""} {
					message'fd $chan $::config::me(server) [list "301" $::dispnames($chan) [lindex $msg 1] $aways([getfdbynick [lindex $msg 1]])
				}
			} {
				foreach {chn} [split [lindex $msg 1] ","] {
					sendtochan $chan $chn "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "PRIVMSG" $chn [lindex $msg 2]]
				}
			}
		}

		"pong" {
			set pings($chan) 1
			message'fd $chan "$::config::me(server)" [list "NOTICE" "*" "Ping? Pong!"]
		}

		"away" {
			set aways($chan) [lindex $msg 1]
		}

		"notice" {
			if {[getfdbynick [lindex $msg 1]] != ""} {
				message'send [lindex $msg 1] "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "NOTICE" [lindex $msg 1] [lindex $msg 2]]
				if {$aways([getfdbynick [lindex $msg 1]])!=""} {
					message'fd $chan $::config::me(server) [list "301" $::dispnames($chan) [lindex $msg 1] $aways([getfdbynick [lindex $msg 1]])
				}
			} {
				foreach {chn} [split [lindex $msg 1] ","] {
					sendtochan $chan $chn "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "NOTICE" $chn [lindex $msg 2]]
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
			if {[lindex $msg 1] != ""} {whois $chan [lindex $msg 1] [string match "*o*" $::modes($chan)]}
		}

		"list" {
			chan'ls $chan
		}

		"who" {
			if {[set niq [getfdbynick [lindex $msg 1]]] != ""} {
				if {$::aways($niq) == ""} {
					set hg "H"
				} {
					set hg "G"
				}
				message'fd $chan $::config::me(server) [list "352" "*" [lindex $msg 1] $::idents($niq) $::hostnames($niq) $::config::me(server) $::dispnames($niq) $hg "1 $::realnames($niq)"]
			} {
				foreach {niq} $rooms([lindex $msg 1]) {
					if {$::aways($niq) == ""} {
						set hg "H"
					} {
						set hg "G"
					}
					message'fd $chan $::config::me(server) [list "352" "*" [lindex $msg 1] $::idents($niq) $::hostnames($niq) $::config::me(server) $::dispnames($niq) $hg "1 $::realnames($niq)"]
				}
			}
			message'fd $chan $::config::me(server) [list "315" [lindex $msg 1] "End of /WHO"]
		}

		"cloakme" {
			global modes
			sendtoneighbut $chan "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "QUIT" "/CLOAKME used; usermode +x set; cycling"]
			append modes($chan) "x"
			sendtoneighchan $chan "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "JOIN" "%chan"]
		}

		"decloakme" {
			global modes
			sendtoneighbut $chan "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "QUIT" "/DECLOAKME used; usermode -x set; cycling"]
			set modes($chan) [string map {x {}} modes($chan)]
			sendtoneighchan $chan "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "JOIN" "%chan"]
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
					set ctr 0
					foreach {l} [split [lindex $msg 2] {}] {
						if {$l == "+"} {set state +; continue}
						if {$l == "-"} {set state -; continue}
						switch -regexp $l {
							"[qaQAzohvbeIOHV]" {chan'chgmode $chan $chn $state $l [lindex $msg [expr {2+[incr ctr]}]]}
							"[imnsptrSCN]" {chan'chgmode $chan $chn $state $l ""}
						}
					}
				} {
					message'fdnoc $chan $::config::me(server) [list "324" "*" $chn "+[chan'retmode $chn]"]
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
			foreach {chn} [split [lindex $msg 1] ","] {apass} [split [lindex $msg 2] ","] {
				set okchan 0
				switch [string index $chn 0] {
					"#" {set okchan 1}
					"&" {set okchan 1}
					"!" {set okchan 1;set $chn "!AAAAA[string range $chn 1 end]"}
					"+" {set okchan 1}
				}
				if {$okchan} {
					if {![info exists apass]} {set apass ""}
					chan'adduser $chan $chn $apass
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

		"server" {
			set approved 0
			foreach {k v} [array get ::config::servers] {
				set pass [dict get $v pass]
				set host [dict get $v host]
				if {
				([lindex $msg 1] == $k)
				&& ([lindex $msg 2] == $pass)
				&& ($::rhostnames($chan) == $host)
				} {
					set approved 1
					set dispnames($chan) "$k"
					append modes($chan) "L"
				}
			}
			if {$approved} {
				global dispnames
				message'fd $chan "$::config::me(server)" [list "NOTICE" $::dispnames($chan) "You are now considered a Server. If you are using an IRC client, please reconnect as this is not correct behaviour."]
			}
		}

		"nick" {
			chgnick $chan [lindex $msg 1]
		}

		"umetadata" {
			set k [lindex $msg 1]
			set v [lindex $msg 2]
			if {$v==""} {dict unset extinfo($chan) umetadata $k} {dict set extinfo($chan) umetadata $k $v}
			message'fd $chan "$::config::me(server)" [list "NOTICE" $::dispnames($chan) "New umetadata line: $k = $v"]
		}

		"quit" {
			client'err $chan "$::idents($chan)@[gethostname $chan]" "$::dispnames($chan)" "Quit: [lindex $msg 1]"
		}

		"part"	{
			foreach {chn} [split [lindex $msg 1] ","] {
				set rooms($chn) [lreplace $rooms($chn) [lsearch -exact $rooms($chn) $chan] [lsearch -exact $rooms($chn) $chan]]
				foreach {l} [split $::opmodes {}] {set rooms(list,$chn,$l) [lreplace $rooms(list,$chn,$l) [lsearch -exact $rooms(list,$chn,$l) $chan] [lsearch -exact $rooms(list,$chn,$l) $chan]]}
				sendtochan $chan $chn "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "PART" $chn "Part: [lindex $msg 2]"]
				message'fd $chan "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "PART" $chn "Part: [lindex $msg 2]"]
			}
		}

		"kick"	{
			set zhan [getfdbynick [lindex $msg 2]]
			foreach {chn} [split [lindex $msg 1] ","] {
				if {[string match "*S*" $::modes($zhan)]} {
					message'fdnoc $chan "$::config::me(server)" [list "484" $room $param "Cannot kick or deop a service"]
					return
				}

				if {![chan'canchgmode $chan $chn "+" "h"]} {continue}
				if {![chan'canchgmode $chan $chn "+" "o"] && [chan'canchgmode $zhan $chn "+" "o"]} {continue}
				if {![chan'canchgmode $chan $chn "+" "a"] && [chan'canchgmode $zhan $chn "+" "a"]} {continue}
				if {![chan'canchgmode $chan $chn "+" "q"] && [chan'canchgmode $zhan $chn "+" "q"]} {continue}
				set rooms($chn) [lreplace $rooms($chn) [lsearch -exact $rooms($chn) $zhan] [lsearch -exact $rooms($chn) $zhan]]
				foreach {l} [split $::opmodes {}] {set rooms(list,$chn,$l) [lreplace $rooms(list,$chn,$l) [lsearch -exact $rooms(list,$chn,$l) $zhan] [lsearch -exact $rooms(list,$chn,$l) $zhan]]}
				sendtochan $chan $chn "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "KICK" $chn [lindex $msg 2] [lindex $msg 3]]
				message'fd $chan "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "KICK" $chn [lindex $msg 2] [lindex $msg 3]]
				message'fd $zhan "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "KICK" $chn [lindex $msg 2] [lindex $msg 3]]
			}
		}
	}
	}
	if {[string match "*L*" $modes($chan)]} {
	switch -nocase [lindex $msg 0] {
		"kill" {
			set killed [getfdbynick [lindex $msg 2]]
			if {[string match "*&*" $killed]} {
				message'serv [lindex [split $killed "&"] 1] "KILL $::config::me(server)&[lindex $msg 1] [lindex $msg 2] :[lindex $msg 3]"
			} {
				client'err $killed "$::idents($killed)@[gethostname $killed]" "$::dispnames($killed)" "Killed ([string map {& !} [lindex $msg 1]] ([lindex $msg 3]))"
			}
		}
		"cmsg" {
			set killed [getfdbynick [lindex $msg 1]]
			sendtochan $chan [lindex $msg 2] "$::dispnames($killed)!$::idents($killed)@[gethostname $killed]" [list PRIVMSG [lindex $msg 2] "[lindex $msg 3]"]
			sendtobutserv $chan "CMSG [lindex $msg 1] [lindex $msg 2] [lindex $msg 3]"
		}
		"user" {
			global dispnames idents hostnames rhostnames realnames modes
			set via [lindex $msg 1]
			set nick [lindex $msg 2]
			set ts [lindex $msg 3]
			set ident [lindex $msg 4]
			set hostname [lindex $msg 5]
			set rhostname [lindex $msg 6]
			set idnick [lindex $msg 7]
			set rname [lindex $msg 9]
			set mode [lindex $msg 8]
			# Nick collision from server: Assume both of us are wrong and kill both users.
			if {[getfdbynick $nick]!=""} {
				set killed [getfdbynick $nick]
				client'err $killed "$::idents($killed)@[gethostname $killed]" "$::dispnames($killed)" "Killed ($::dispnames($chan) ([lindex $msg 2]))"
				message'serv $chan "KILL $::config::me(server) $nick :Nickname collision; TS not used."
			}
			set dispnames("$idnick&$via") $nick
			set rhostnames("$idnick&$via") $rhostname
			set hostnames("$idnick&$via") $hostname
			set idents("$idnick&$via") $ident
			set realnames("$idnick&$via") $rname
			set modes("$idnick&$via") $mode
			sendtobutserv $chan "USER $::config::me(server)&$via [join [lrange $msg 2 7] " "] :[lindex $msg 8]"
		}
		"ucmd" {
			set umsg "[join [lrange $msg 2 end-1] " "] :[lindex $msg end]"
			client'rreg [getfdbynick $nick] $umsg
		}
		"urep" {
			set umsg "[join [lrange $msg 3 end-1] " "] :[lindex $msg end]"
			set killed [getfdbynick [lindex $msg 2]]
			if {[string match "*&*" $killed]} {
				message'serv [lindex [split $killed "&"] 1] "UREP $::config::me(server)&[lindex $msg 1] $umsg"
			} {
				putss $killed ":[lindex [split [lindex $msg 1] "&"] 0] $umsg"
			}
		}
		"server" {
			global modes dispnames
			set via [lindex $msg 1]
			set nick [lindex $msg 2]
			append modes($nick) L
		}
	}
	}
	if {![string match "*L*" $modes($chan)] && [string match "*o*" $modes($chan)]} {
	switch -nocase [lindex $msg 0] {
		"kill" {
			set killed [getfdbynick [lindex $msg 1]]
			if {[string match "*&*" $killed]} {
				message'serv [lindex [split $killed "&"] 1] "KILL $::config::me(server)&[lindex $msg 1] [lindex $msg 2] :[lindex $msg 3]"
			} {
				client'err $killed "$::idents($killed)@[gethostname $killed]" "$::dispnames($killed)" "Killed ([string map {& !} [lindex $msg 1]] ([lindex $msg 3]))"
			}
			#client'err $killed "$::idents($killed)@[gethostname $killed]" "$::dispnames($killed)" "Killed ($::dispnames($chan) ([lindex $msg 2]))"
		}
		"sethost" {
			global hostnames
			if {""==[lindex $msg 1]} {
				message'fd $chan $::config::me(server) [list "NOTICE" [getnickbyfd $chan] "You need to specify a host to change to"]
			}
			sendtoneighbut $chan "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "QUIT" "/CHGHOST or /SETHOST used; cycling"]
			set hostnames($chan) [lindex $msg 1]
			append modes($chan) "x"
			sendtoneighchan $chan "$::dispnames($chan)!$::idents($chan)@[gethostname $chan]" [list "JOIN" "%chan"]
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
			sendtoneighbut $zhan "$::dispnames($zhan)!$::idents($zhan)@[gethostname $zhan]" [list "QUIT" "/CHGHOST or /SETHOST used; cycling"]
			set hostnames($zhan) [lindex $msg 2]
			append modes($zhan) "x"
			sendtoneighchan $zhan "$::dispnames($zhan)!$::idents($zhan)@[gethostname $zhan]" [list "JOIN" "%chan"]
		}
	}
	}
}

proc is_maskmode {chan lm zhan} {
	set mask "$::dispnames($zhan)!$::idents($zhan)@[gethostname $zhan]"
	set rmask "$::dispnames($zhan)!$::idents($zhan)@$::rhostnames($zhan)"
	if {![info exists ::(list,$chan,$lm)]} {return 0}
	foreach {entry} $::rooms(list,$chan,$lm) {
		if {[string match -nocase $entry $mask]} {
			return 1
		}
		if {[string match -nocase $entry $rmask]} {
			return 1
		}
	}
	return 0
}

proc is_anyop {room fd} {
	foreach {letter} [split $::opmodes {}] {
		if {[lsearch -exact $::rooms(list,$room,$letter) $sf]} {return 1}
	}
	return 0
}

proc is_anyvoice {room fd} {
	foreach {letter} [split $::opmodes {}] {
		if {[lsearch -exact $::rooms(list,$room,$letter) $sf]} {return 1}
	}
	if {[lsearch -exact $::rooms(list,$room,v) $sf]} {return 1}
	return 0
}

proc sendtochan {sf room src zarg} {
	if {![info exists ::rooms($room)]} {return}
	if {![lsearch -exact $::rooms($room) $sf] && ![lsearch -exact $::rooms(list,$room,o) $sf] && ![lsearch -exact $::rooms(list,$room,v) $sf] && ![lsearch -exact $::rooms(list,$room,h) $sf] && [hasmode $room "n"]} {
		message'fd $sf "$::config::me(server)" [list "404" [lindex [split $src "!"] 0] $room "Cannot send to channel; you need to enter"]
		return
	}
	if {![lsearch -exact $::rooms(list,$room,o) $sf] && [hasmode $room "m"]} {
		if {![lsearch -exact $::rooms(list,$room,h) $sf]} {
			if {![lsearch -exact $::rooms(list,$room,v) $sf]} {
				message'fd $sf "$::config::me(server)" [list "404" [lindex [split $src "!"] 0] $room "Cannot send to channel; you need at least VOICE"]
			}
		}
		return
	}
	if {[is_maskmode $room b $sf] && ![lsearch -exact $::rooms(list,$room,o) $sf] && ![lsearch -exact $::rooms(list,$room,v) $sf] && ![lsearch -exact $::rooms(list,$room,h) $sf]} {
		message'fd $sf "$::config::me(server)" [list "404" [lindex [split $src "!"] 0] $room "Cannot send to channel; you are banned."]
		return
	}
	if {[is_maskmode $room z $sf] && ![lsearch -exact $::rooms(list,$room,o) $sf] && ![lsearch -exact $::rooms(list,$room,v) $sf] && ![lsearch -exact $::rooms(list,$room,h) $sf]} {
		message'fd $sf "$::config::me(server)" [list "404" [lindex [split $src "!"] 0] $room "Cannot send to channel; you are quieted."]
		return
	}
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
	putss $chan ":$::config::me(server) ERROR :Closing link: $nick\[$addr\] ($reason)"
	chan close $chan
	client'eoc $chan "$reason"
	foreach {room nqls} [array get ::rooms] {
		if {[string match "list,*" $room]} {continue}
		if {[lsearch -exact $nqls $chan] != -1} {set rooms($room) [lreplace $nqls [lsearch -exact $nqls $chan] [lsearch -exact $nqls $chan]]}
		if {[lsearch -exact $nqls $chan] != -1} {set rooms(list,$room,o) [lreplace $rooms(list,$room,o) [lsearch -exact $rooms(list,$room,o) $chan] [lsearch -exact $rooms(list,$room,o) $chan]]}
		if {[lsearch -exact $nqls $chan] != -1} {set rooms(list,$room,h) [lreplace $rooms(list,$room,h) [lsearch -exact $rooms(list,$room,h) $chan] [lsearch -exact $rooms(list,$room,h) $chan]]}
		if {[lsearch -exact $nqls $chan] != -1} {set rooms(list,$room,v) [lreplace $rooms(list,$room,v) [lsearch -exact $rooms(list,$room,v) $chan] [lsearch -exact $rooms(list,$room,v) $chan]]}
	}
}

proc client'eoc {chan reason} {
	global rooms dispnames realnames idents hostnames extinfo rhostnames modes
	set dn $dispnames($chan)
	set dispnames($chan) ""
	sendtoneighbut $chan "${dn}!$::idents($chan)@[gethostname $chan]" [list "QUIT" "$reason"]
	unset realnames($chan)
	unset idents($chan)
	unset hostnames($chan)
	unset rhostnames($chan)
	if {[info exists extinfo($chan)]} {unset extinfo($chan)}
	if {[info exists modes($chan)]} {unset modes($chan)},
}

proc message'send {nick src zarg} {
	set wrt ":$src"
	append wrt " [join [lrange $zarg 0 end-1] " "]"
	append wrt " :[lindex $zarg end]"
	putss [getfdbynick $nick] "$wrt"
}

proc message'fd {nick src zarg} {
	set wrt ":$src"
	append wrt " [join [lrange $zarg 0 end-1] " "]"
	append wrt " :[lindex $zarg end]"
	putss $nick "$wrt"
}

proc putss {fd msg} {
	catch {puts $fd $msg} fff
}

proc message'fdnoc {nick src zarg} {
	set wrt ":$src"
	append wrt " [join [lrange $zarg 0 end-1] " "]"
	append wrt " [lindex $zarg end]"
	putss $nick "$wrt"
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
#	foreach {revsuf} $::config::me(reversesuffixes) {
#		set treve [::dns::resolve -timeout 10000 -type PTR "$dnsddr.$revsuf"]
#		::dns::wait $treve
#		set reve [lindex [::dns::address $treve] 0]
#
#		set taaa [::dns::resolve -timeout 10000 -type A $reve]
#		set taaaaa [::dns::resolve -timeout 10000 -type AAAA $reve]
#		::dns::wait $taaa
#		::dns::wait $taaaaa
#		set aaa [lindex [::dns::address $taaa] 0]
#		set aaaaa [lindex [::dns::address $taaaaa] 0]
#		putss stdout "$reve $aaa $aaaaa"
#		if {""!=$aaa} {
#			if {$aaa==$addr} {
#				message'fd $chan $::config::me(server) [list "020" "*" "*** Found your hostname: $reve The LAST of these messages takes precedence."]
#				set rhostnames($chan) $reve
#				set ctr 0
#				set zddr ""
#				foreach {x y} [split $reve "."] {
#					incr ctr
#					if {$ctr >= 3} {break}
#					set w "$x"
#					append w "$y"
#					set srl [string length $w]
#					set newad [string range [::md5::md5 -hex $w] 0 11]
#					if {$ctr != 1} {append zddr "."}
#					append zddr "$newad"
#				}
#				foreach {x} [lrange [split $reve "."] 2 end] {
#					append zddr ".$x"
#				}
#				set hostnames($chan) $reve
#			}
#		}
#		if {""!=$aaaaa} {
#			if {$aaaaa==$addr} {
#				message'fd $chan $::config::me(server) [list "020" "*" "*** Found your hostname: $reve The LAST of these messages takes precedence."]
#				set rhostnames($chan) $reve
#				set ctr 0
#				set zddr ""
#				foreach {x y} [split $reve "."] {
#					incr ctr
#					if {$ctr >= 3} {break}
#					set w "$x"
#					append w "$y"
#					set srl [string length $w]
#					set newad [string range [::md5::md5 -hex $w] 0 11]
#					if {$ctr != 1} {append zddr "."}
#					append zddr "$newad"
#				}
#				foreach {x} [lrange [split $reve "."] 2 end] {
#					append zddr ".$x"
#				}
#				set hostnames($chan) $reve
#			}
#		}
#		if {""==$aaa&&""==$aaaaa} {
#		message'fd $chan $::config::me(server) [list "020" "*" "*** Could not look up your hostname."]
#		}
#	}
