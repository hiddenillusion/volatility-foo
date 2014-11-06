#!/bin/bash

####################################################
# Automate2.0.sh was created by Glenn P. Edwards Jr.
#	 	http://hiddenillusion.blogspot.com
# 				@hiddenillusion
# Version 0.1 
# Date: 2012
# Compatability: written/tested for volatility 2.0
####################################################
# To - Do #
# General
#	- latest windows branch isn't working with malware.py so moved that trunk to "windows_latest" folder and put stable 2.0 branch as "windows"
#	- fails when the memory image has spaces in its name ...
#	- add update functionality to get latest trunk/branches?
# windows alpha changes
# 	- Plugins
#		- evtlogs (XP/W2k3 only)
#	- win version specific checks

# Defining some stuff...
Date=`date +%m-%d-%Y_%T`

# Volatility locations
vol_win="/path/to/volatility/vol.py" #stable release
vol_alpha="/path/to/volatility_alpha/vol.py"
vol_linux="/path/to/volatility_linux/vol.py"
vol_mac="/path/to/volatility_mac/vol.py"

########################################
# Define the overall volatility branches 
########################################
# - This array should contain what you defined above 
#	so you can choose which branch to use if the default 
#	test for profile identification fails.
vol_branches=("$vol_win" "$vol_alpha" "$vol_linux" "$vol_mac");

YARA_Rules="/path/to/rules.yara"
# Change if you only want to use a single YARA rules file, otherwise it will put all listed in array
#YARA_Rules=(`find /path/to/yara/rules -type f -iname *.yara -exec ls {} \;`);

Usage()
{
version=1.1
echo "[*] `basename $0` version: $version written by Glenn P. Edwards Jr."
	echo "Usage : `basename $0` [options]"
                echo "  OPTIONS:"
                echo "          Required"
                echo "          -f <file>       : set the memory dump file"
				echo ""
                echo "          Optional"
                echo "          -b              : specify which branch to use instead of using the default"                
                echo "          -c              : convert memory dump to a raw DD image and save it to PWD (crashdump, hibernation file etc.)" 
                echo "          -d              : enable dumping of carved files (DLL/EXE/SYS)"
                echo "          -j              : set how many forked processes/jobs to use (default is 10)"
                echo "          -o <directory>  : set the case directory (PWD is set by default)"
                echo "          -P              : specify which profile to use instead of trying to auto determine it"
                echo "          -t <mm:ss>      : set the time out for how long a plugin can run (default is 5 mins)"
                echo "          -h              : print this message"
	exit
}

while getopts "b:cdf:hj:o:t:P:" opt ;do
	case $opt in
	b) Vol_Specified=$OPTARG;;        	
	c) Convert=yes;;
	d) Dump=yes;;
	f) MemDump=$OPTARG;;
	h) Usage
		exit;;
	j) Jobs=$OPTARG;;
	o) Case_Dir=$OPTARG;;
	t) Timer=$OPTARG;;
	P) Profile_Specified=$OPTARG;;
	esac
done

# Taking a look at the options provided
if [[ -z $MemDump ]]; then
     Usage
     exit
fi

if [[ $Convert == "yes" ]]; then
	echo "[-] Trying to convert the memory dump..."
	$vol_win -f $MemDump imagecopy -O converted.$Date.raw
	wait
	if [ -f converted.$Date.raw ]; then
		echo "[-] Converted file saved to : `echo $PWD/converted.$Date.raw`"
	fi
	exit
fi

if [[ -z $Jobs ]]; then
	Jobs=10
fi

# Making sure we have the required directories created
if [[ -z $Case_Dir ]]; then
        Case_Dir=`echo $PWD`
else
	if [ -d $Case_Dir ]; then
		echo "[-] The Case Dir '$Case_Dir' already exists...this analysis will be created as a subdirectory"
	else
		mkdir $Case_Dir
		if [[ $? -ne 0 ]]; then
			echo "[!] Failed to make the Case Dir '$Case_Dir'...incorrect permissions?"
			exit 1
		fi
	fi
fi

# Just for safe keepings - in case something like the $Date variable is changed
Mem_Dir="$Case_Dir/memory_analysis.$Date"
if [ -d $Mem_Dir ]; then
	echo "[!] The Mem Dir '$Mem_Dir' already exists - this must be unique"
	exit 1
else
	mkdir $Mem_Dir
fi

#####################################
# Plugins to run for a given analysis
#####################################
# - Add/Remove/Modify parameters as needed.

# General plugins to use for _any_ Windows image profile
win_general_plugins=("psscan" "pslist" "psxview" "dlllist" "handles" "mutantscan" "svcscan" "ssdt" "filescan" "vadinfo" "callbacks" "modules" "modscan" "ldrmodules -v" "driverirp --verbose");

##################################################
# Specific plugins based on image profiles version
##################################################
# - v2.0 didn't include the profile specific stuff so this is manual
winxp_network_plugins=("connscan" "sockets" "sockscan" "connections");
win7_network_plugins=("netscan");
linux_plugins=("linux_arp" "linux_cpuinfo" "linux_dmesg" "linux_dump_map" "linux_ifconfig" "linux_list_open_files" "linux_lsmod" "linux_mount" "linux_netstat" "linux_proc_maps" "linux_route" "linux_route_cache" "linux_task_list_ps" "linux_task_list_psaux" "linux_tasklist_kmem_cache");
# mac_plugins=(....)

##############################################################
# Dump plugins which require special switches/dump directories
##############################################################
if [[ $Dump == "yes" ]]; then
        defined_dumps=("dlldump" "moddump" "vaddump" "zeroaccess");
        for plugin in "${defined_dumps[@]}"; do
                if [ ! -d $Mem_Dir/$plugin ]; then
					mkdir $Mem_Dir/$plugin
                fi
                dump_plugins=("${dump_plugins[@]}" "$plugin -D $Mem_Dir/$plugin");
        done
fi

###########################################
# Setting up a log of the analysis process
###########################################
process_log="$Mem_Dir/process.log"
exec &> >(tee -a $process_log)

#####################################################
# Start the timer to see how long the analysis takes
#####################################################
tic=$(date +%s)

###############################################################################
# Setting up a log for killing hung plugins based on the timeout value supplied
###############################################################################
# - This is because I've encounted certain plugins hanging during analysis so to 
#	make sure they don't halt the process from completing we need a safety timer.  
#	It isn't an _exact_ timer since it's not spawned with the cmd but saves 
#	resources and is just a safety net.  It's bash to it's nothing crazy, but it
#	gets the job done.
touch "$Mem_Dir/fpids.$$.tmp"
forked_pids="$Mem_Dir/fpids.$$.tmp" 

if ! [[ -z $Timer ]]; then
	if ! [[ $Timer =~ [0-9]{2}:[0-9]{2} ]]; then
		echo "[!] Timer value is incorrect"
		exit 1
	fi
else
	Timer="05:00"	

fi

timer_loop ( ){
	Duration=`date "+%s" -d "$Timer"`
	tmp_file=`mktemp`                        
	while [ -f $tmp_file ]; do
		rm $tmp_file
		cat $forked_pids | grep -v "^$" | while read pid; do
			ps | grep $pid > /dev/null
			if [ $? -eq 0 ] ;then
				touch $tmp_file
				ptime=`ps -p $pid -o pid,etime | awk '{print $2}' | tail -1 | grep -v ELAPSED`
				psec=`date "+%s" -d "$ptime"`
				if [ $psec -gt $Duration ]; then
					echo "[-] Killing PID: $pid , ptime: $ptime > Timer: $Timer"
					kill -9 $pid &> /dev/null
				fi
				sleep 5s	
			fi
		done
	done
}


main() {
	echo "[+] Analysis started at: `date`"
        echo "[-] Forking set to : '$Jobs' jobs"
        display_timer=$(echo "$Timer" | awk -F: '{print $1 "m", $2 "s"}')
        echo "[-] Plugin timer set to : '$display_timer'"
        echo "[-] Running the script as PID: $$"
        echo "[+] Case Dir set to :  '$Case_Dir'"
        echo "[+] Memory Dir set to : '$Mem_Dir'"

        ########################################
        # Functions to fork the plugin analysis
        ########################################
        # - again, it's bash so don't hate.        
        run_win_plugins ( ){
		echo "[-] Syntax executed : $Vol_Specified -f $MemDump --profile=$Profile_Specified $cmd" | tee &>> $process_log $Mem_Dir/$cmd_log.txt
		$vol_win -f $MemDump --profile=$Profile_Specified $cmd >> $Mem_Dir/$cmd_log.txt & pid=$!
		echo $pid >> $forked_pids
		echo "[-] - Forking PID: $pid" &>> $process_log
        }
        run_linux_plugins ( ){
		echo "[-] Syntax executed : $vol_linux -f $MemDump --profile=$Profile_Specified $cmd_log" | tee &>> $process_log $Mem_Dir/$cmd_log.txt
		$vol_linux -f $MemDump --profile=$Profile_Specified $cmd_log >> $Mem_Dir/$cmd_log.txt & pid=$!
		echo $pid >> $forked_pids
        }
        run_procexedump_plugin ( ){
		echo "[-] Syntax executed : $Vol_Specified -f $MemDump --profile=$Profile_Specified -p $p procexedump -D $Mem_Dir/procexedump" | tee &>> $process_log $Mem_Dir/procexedump.txt 
		$Vol_Specified -f $MemDump --profile=$Profile_Specified -p $p procexedump -D $Mem_Dir/procexedump >> $Mem_Dir/procexedump.txt & pid=$!
		echo $pid >> $forked_pids
		echo "[-] PID $pid: --- Forking procexedump" &>> $process_log
        }
	run_malfind_plugin ( ){
		echo "[-] Syntax executed : $Vol_Specified -f $MemDump --profile=$Profile_Specified malfind -Y $rule -D $Mem_Dir/malfind" | tee &>> $process_log $Mem_Dir/malfind.txt
		$Vol_Specified -f $MemDump --profile=$Profile_Specified malfind -Y $rule -D $Mem_Dir/malfind >> $Mem_Dir/malfind.txt & pid=$!
		echo $pid >> $forked_pids
		echo "[-] PID $pid: --- Forking malfind" &>> $process_log
        }

	###########################################################
	# Run specific plugins based on the image profiles' version
	###########################################################
	if [[ $Profile_Specified == Linux* ]]; then
		plugins=("${linux_plugins[@]}")	
		
		# Parse the commands from the Linux array
		for cmd in "${plugins[@]}"; do
			cmd_log=`echo $cmd | awk '{print $1}'`
			run_win_plugins $cmd & pid=$!
			while [ `jobs | wc -l` -ge $Jobs ]; do
				sleep 1s
			done
			echo "[-] PID $pid: -- Starting $cmd"
		done
		
		# Cleanup for hung Linux plugins
		timer_loop

   	elif [[ $Profile_Specified == WinXP* ]] || [[ $Profile_Specified == Win2K3* ]]; then
			plugins=("${win_general_plugins[@]}" "${winxp_network_plugins[@]}")
	elif [[ $Profile_Specified == Vista* ]] || [[ $Profile_Specified == Win7* ]]; then
			plugins=("${win_general_plugins[@]}" "${win7_network_plugins[@]}")
	fi
	
	if [[ $Dump == "yes" ]]; then
		echo "[+] Dumping is enabled... this may take some time"
		plugins=("${plugins[@]}" "${dump_plugins[@]}")
	fi		
	
	# Parse the commands from the Windows array(s)
	for cmd in "${plugins[@]}"; do
		cmd_log=`echo $cmd | awk '{print $1}'`
		run_win_plugins & pid=$!
		while [ `jobs | wc -l` -ge $Jobs ]; do
			sleep 1s
		done
		echo "[-] PID $pid: -- Starting $cmd_log"
	done

	# Cleanup for hung Windows plugins
	timer_loop

	# mac profile ...

	if [[ $Dump == "yes" ]]; then		
	# procexedump is being run separately because the way it's being called is dependent on psscan 
	# results to feed what it should dump. I wanted to use psscan instead of the default pslist it uses
	# and I didn't want to have to create another plugin/modify the source because I wanted this script
	# to work out of the box without any additional requirements - and as such, you get this ... I know
	# it's definitely not the best as it adds much much more than is needed but oh well.
	# If you take out any of the plugins which produce the output for the files which are being waited 
	# for below it will cause an infinite loop so make sure to comment these out if you choose to not 
	# include these plugins.
		while true; do
			if [[ -f $Mem_Dir/psscan.txt ]] && ! [[ `lsof | grep $Mem_Dir/psscan.txt &> /dev/null` ]]; then
				echo "[-] PID $$: -- Started procexedump"
		                if [ ! -d $Mem_Dir/procexedump ]; then
							mkdir $Mem_Dir/procexedump
		                fi
                		cat $Mem_Dir/psscan.txt | awk '{print $3}'| while read p; do
							if [[ "$p" =~ [0-9]+ ]]; then
								run_procexedump_plugin &
									while [ `jobs | wc -l` -ge $Jobs ]; do
										sleep 1s
									done
							fi
						done
				break
			else
				sleep 5s
			fi
		done	
	
		# Passing all YARA rule files defined above to malfind
		echo "[-] PID $$: -- Started malfind"
		if [ ! -d $Mem_Dir/malfind ]; then
			mkdir $Mem_Dir/malfind
		fi
		for rule in "${YARA_Rules[@]}"; do
			run_malfind_plugin &
			while [ `jobs | wc -l` -ge $Jobs ]; do
				sleep 1s
			done
		done
		
		# Cleanup for hung dump plugins
		timer_loop
	fi

	#######################
	# Post-processing stuff
	#######################
	# - If you take out any of the plugins which produce the output for the files 
	#	which are being waited for below it will cause an infinite loop so make 
	#	sure to comment these out if you choose to not include these plugins.
	# - This can obviously be seperated so it doesn't halt your initial memory analysis
	while true; do
		if [[ -f $Mem_Dir/ssdt.txt ]] && ! [[ `lsof | grep $Mem_Dir/ssdt.txt &> /dev/null` ]]; then
			mv $Mem_Dir/ssdt.txt $Mem_Dir/ssdt.tmp
			cat $Mem_Dir/ssdt.tmp | egrep -v -i '(ntoskrnl|win32k)' > $Mem_Dir/ssdt.txt
			rm $Mem_Dir/ssdt.tmp
			break
		else
			sleep 5s
		fi
	done

	while true; do
		if [[ -f $Mem_Dir/handles.txt ]] && ! [[ `lsof | grep $Mem_Dir/handles.txt &> /dev/null` ]]; then                
			mv $Mem_Dir/handles.txt $Mem_Dir/handles.tmp
			cat $Mem_Dir/handles.tmp | awk '{ if($4 !~ /^$/) {print $0}}' | grep -v "''" > $Mem_Dir/handles.txt
			rm $Mem_Dir/handles.tmp		
			break
		else
			sleep 5s
		fi
	done
}

selector() {
        echo "[!] Could not determine a profile to use.  Verify this is a valid memory dump and that it isn't corrupt or have spaces in its name."
        echo "[-] Would you like to choose a different volatility branch for profile identification? [y/n]"
        read answer
        if [[ $answer == "y" ]]; then
                count=0
                echo "[-] Available volatility branches to select from:"
                for branch in "${vol_branches[@]}"; do
                        echo "$count. $branch"
                        ((count++))
                done
                echo "[-] Enter the selected branch #:"
                read branch_choice
                selected_branch=$(echo ${vol_branches[$branch_choice]})
                if [[ -z $selected_branch ]]; then
                        echo "[-] Selected branch not found ... did you mistype it?"
                        exit 1
                fi

                echo "[-] Selected branch to use is : '$selected_branch'"
                echo "[-] Determining profiles available for selected branch..."
                profile_list=(`$selected_branch --info | awk '/PROFILES/ ,/^$/' | grep -v '^$'  | awk  'FNR>2' | awk -F- '{print $1}'`)

				count=0
                for pro in "${profile_list[@]}"; do
					echo "$count. $pro"
					((count++))
                done

                echo "[-] Enter the selected profile #."
                read profile_choice
                selected_profile=$(echo ${profile_list[$profile_choice]})
                if [[ -z $selected_profile ]]; then
                        echo "[-] Selected profile not found ... did you mistype it?"
                        exit 1
                elif [[ "$profile_choice" =~ [0-9]+ ]]; then
					echo "[-] Selected profile to use is : '$selected_profile'"
					Vol_Specified=$selected_branch
					Profile_Specified=$selected_profile
					main

                else
					exit
                fi
        else
			exit
        fi
}

# Using the default stable Windows branch listed below, unless explicitly defined
if [[ -z $Vol_Specified ]]; then
	Vol_Specified=$vol_win
	echo "[-] Using the default Volatility branch : $Vol_Specified"
else
	echo "[-] Volatility branch manually set to : $Vol_Specified"
fi

# Trying to identify which profile to feed volatility by taking the first match, unless explicitly defined
if [[ -z $Profile_Specified ]]; then
	Profile_Specified=`$Vol_Specified imageinfo -f $MemDump | grep "Suggested Profile" | awk '{print $4}' | sed 's/,$//'`
	echo "[+] Trying to identify the image"
	echo "[-] The identified profile to use is: $Profile_Specified"
else
	echo "[-] Profile manually set to : $Profile_Specified"
fi

if [[ $Profile_Specified == Win* ]] || [[ $Profile_Specified == Vista* ]] || [[ $Profile_Specified == Linux* ]]; then
	main
else
	selector
fi
# mac profile...

# Delete any empty files that were produced & the forked pid trackers
echo "[-] Deleting any empty directories/files from analysis"
find $Mem_Dir -type f -size 0 -exec rm -v {} \; &>> $process_log
find $Mem_Dir -type d -empty -exec rm -rfv {} \; &>> $process_log
rm -rfv $forked_pids &>> $process_log

# End the analysis timer
toc=$(date +%s)
total=$(expr $toc - $tic)
min=$(expr $total / 60)
sec=$(expr $total % 60)
echo "Analysis took :" $min"m":$sec"s"
