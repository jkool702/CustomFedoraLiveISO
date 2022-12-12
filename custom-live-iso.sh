#!/usr/bin/bash

# # # # # # # # # # # # # # SET PARAMETERS  # # # # # # # # # # # # # # # # # 
# all paramaters (except for customIsoUSBDevPath) will be assigned default values or assigned via a user-interactive prompt if left blank

#customIsoReleaseVer=37							# Fedora release version to use. Default is to try to extract it from the base iso filename.
#customIsoTmpDir=/tmp/customIso 		   		# main directory where everything is stored. Defaults to /var/tmp (on disk) if you have <32 gfb ram, and to /tmp (ramdisk) if you have >= 32 gb ram
#customIsoRootfsDir="${customIsoTmpDir}"/rootfs # where the unsquashed live ISO rootfs.img is stored
#customIsoRootfsMountPoint="${customIsoTmpDir}"/sysroot			# where to mount the live ISO rootfs while you modify it
#customIsoFsLabel='FEDORA-37-KDE-LIVE-CUSTOM' 	# filesystem label. Default is "${origIsoFileName%.iso}-CUSTOM"
#customIsoLabelShort='F37-KDE-LIVE' 			# short filesystem label
#customIsoUSBDevPath=/dev/sdk 					# dev path for usb to write ISO to. Leave blank to just make the ISO without burning it to a USB
#rootfsSizeGB=16 								# this is how much space youll have in the live OS. Because this is in a squashfs increasing the free space doesnt really increase the ISO size much. Default is 16 GB.
useNvidiaFlag=true   							# true/false. this adds stuff to the dracut (drivers + kernel cmdline) to *hopefully* make the nvidia modules load and not the nouveau ones. default depends on if there is any trace on nvidia on the host system.

# TO USE PRE-DOWNLOADED IMAGE, SPECIFY origIsoSource="file://<path>" --OR-- leave origIsoSource blank and place/link the ISO somewhere under $customIsoTmpDir
# if left blank, you will be promoted to choose one of the current fedora "respins" to download OR to choose a local ISO found somewhere under $customIsoTmpDir
#origIsoSource='https://dl.fedoraproject.org/pub/fedora/linux/releases/37/Spins/x86_64/iso/Fedora-KDE-Live-x86_64-37-1.7.iso'
#origIsoSource='https://dl.fedoraproject.org/pub/alt/live-respins/F37-KDE-x86_64-LIVE-20221201.iso'
#origIsoSource='file:///home/${USER}/F37-KDE-x86_64-LIVE-20221201.iso'

# # # # # # # # # # # # # # BEGIN SCRIPT # # # # # # # # # # # # # # # # # 

# set selinux to permissive
setenforce 0

dirAutoRename() {
	# if the input directory exists, rename it to ${ORIGNAME}_N, where N is the lowest non-negative integer such that ${ORIGNAME}_N doesnt exist
	local dirIn
	local -i kk
	for dirIn in "${@}"; do
		if [[ -d "${dirIn}" ]]; then
			kk=0
			while [[ -d "${dirIn}_${kk}" ]]; do 
				((kk++))
			done
			mv "${dirIn}" "${dirIn}_${kk}"
		fi
	done
}

# set trap for cleanup
cleanup_umount() {
	local nn
	mapfile -t umountPaths < <(cat /proc/mounts | awk '{print $2}' | grep -F -f <(printf '%s\n' "${customIsoRootfsMountPoint}" "${customIsoTmpDir}"))
	for nn in "${umountPaths[@]}"; do
		umount -R "${nn}"
		grep -q -F "$nn" /proc/mounts && umount -R -f "${nn}" && grep -q -F "$nn" /proc/mounts && umount -R -f -l "${nn}"
	done
	exit
}
trap cleanup_umount EXIT INT TERM ABRT


customIso_init() {
    # check inputs and set defaults
    [[ -z ${customIsoTmpDir} ]] && customIsoTmpDir="$( (( $(lsmem | grep 'Total online memory' | awk -F ':' '{print $2}' | sed -E s/'^[ \t]*([0-9]*)G.*$'/'\1'/) < 32 )) && echo '/var')"'/tmp/customIso' 
    customIsoTmpDir="${customIsoTmpDir%/}"
    [[ -z ${customIsoRootfsDir} ]] && customIsoRootfsDir="${customIsoTmpDir}"/rootfs 
    [[ -z ${customIsoRootfsMountPoint} ]] && customIsoRootfsMountPoint="${customIsoTmpDir}"/sysroot
    { [[ -n ${useNvidiaFlag} ]] && { [[ ${useNvidiaFlag} == true ]] || [[ ${useNvidiaFlag} == false ]]; }; } || { { rpm -qa | grep -qi nvidia || lshw | grep -qi nvidia; } && useNvidiaFlag=true || useNvidiaFlag=false; } 
    { [[ -n ${rootfsSizeGB} ]] && echo "${rootfsSizeGB}" | grep -q -E '%[0-9]*[1-9]+[0-9]*$'; } || rootfsSizeGB=16
    
    # Install dependencies. Note: this probably isnt a complete list of all required dependencies. Let me know of any Ive missed and Ill add them.
    sudo dnf install git 'livecd*' 'lorax*' systemd-container lshw wget isomd5sum '*kickstart*' qemu qemu-kvm syslinux systemd-container dracut-live isomd5sum mock
    
    # make directories
    mkdir -p "${customIsoTmpDir}"/mnt/iso_old
    mkdir -p "${customIsoRootfsDir}"
    mkdir -p "${customIsoRootfsMountPoint}"
}

customIso_init
 
customIso_getOrigIso () { 
    # move to main working dir
    cd "${customIsoTmpDir}" 
    
    # select and download respin if `origIsoSource` not given
    until [[ -n ${origIsoSource} ]]; do
    	PS3='please select fedora-live respin ISO image to download and customize: '
    	select origIsoSource in $(wget --spider https://dl.fedoraproject.org/pub/alt/live-respins/ -r -l 1 2>&1 | grep -F 'https://dl.fedoraproject.org/pub/alt/live-respins' | sed -E s/'^.*\/'// | grep -E '^F') 'SELECT LOCAL ISO (NO DOWNLOAD)'
    	do
    		echo "YOU CHOSE ${origIsoSource}"
    		if [[ "${origIsoSource}" == 'SELECT LOCAL ISO (NO DOWNLOAD)' ]]; then
    			if [[ -n $(find "${customIsoTmpDir}" -type f -iname '*.iso') ]]; then
    				PS3="Please choose local iso file (found under ${customIsoTmpDir}) to use: "
    				select origIsoSource in 'GO BACK TO PREVIOUS MENU' $(find "${customIsoTmpDir}" -type f -iname '*.iso' | sed -E s/'^'/'file:\/\/'/)
    				do
    				       	(( REPLY == 1 )) && origIsoSource=''
					break 
    				done
    			else
    				echo -e "NO ISO FILES FOUND UNDER ${customIsoTmpDir}! \nPlease add one here or select one of a respin to download" >&2
					origIsoSource=''
    			fi
    
    		else	
    			origIsoSource="https://dl.fedoraproject.org/pub/alt/live-respins/${origIsoSource}" 
    		fi
		break
    	done
    done
    
    echo "The live ISO image will be sourced from ${origIsoSource}" 
    
    # get fedora image from internet (using wget) or link from file
    origIsoFileName="${origIsoSource##*/}"
    if echo "${origIsoSource}" | grep -qE '^file:\/\/'; then
    	origIsoFilePath="${origIsoSource#file:\/\/}"
    else
    	wget "${origIsoSource}"
    	origIsoFilePath="${customIsoTmpDir}/${origIsoFileName}"
    fi
    [[ -z ${customIsoFsLabel} ]] && customIsoFsLabel="${origIsoFileName%.iso}-CUSTOM"
}

customIso_getOrigIso   

customIso_prepRootfs() {   
    # mount original iso image
    mount "${origIsoFilePath}" "${customIsoTmpDir}"/mnt/iso_old
    
    # unsquash root filesystem
    unsquashfs -d "${customIsoRootfsDir}" -f -x "$(find "${customIsoTmpDir}"/mnt/iso_old/ -type f -name 'squashfs.img')"
    customIsoRootfsPath="$(find "${customIsoRootfsDir}" -type f -name 'rootfs.img')"
    
    # zero-pad image to ${rootfsSizeGB} GiB
    dd if=/dev/zero count=$((( ( ( ${rootfsSizeGB} * ( 2 ** 30 ) )  - $(du "${customIsoRootfsPath}" --bytes | awk '{print $1}') ) / ( 2  ** 20 ) ))) bs=$((( 2 ** 20 ))) >> "${customIsoRootfsPath}"
    dd if=/dev/zero bs=$((( ( ${rootfsSizeGB} * ( 2 ** 30 ) )  - $(du "${customIsoRootfsPath}" --bytes | awk '{print $1}') ))) count=1 >> "${customIsoRootfsPath}"
    
    umount -R "${customIsoRootfsMountPoint}"
    umount -R "${customIsoRootfsPath}"

    # extend ext4 filesystem 
    e2fsck -f "${customIsoRootfsPath}"
    resize2fs "${customIsoRootfsPath}" -b
    resize2fs "${customIsoRootfsPath}"
    
    # umount orig iso and mount unsquashed rootfs
    umount "${customIsoTmpDir}"/mnt/iso_old
    mount "${customIsoRootfsPath}" "${customIsoRootfsMountPoint}"
    
    # extract Fedora version from rootfs
    { [[ -n ${customIsoReleaseVer} ]] && echo "${customIsoReleaseVer}" | grep -q -E '^[0-9]*[1-9]+[0-9]*$'; } || customIsoReleaseVer="$(find "${customIsoRootfsMountPoint}"/lib/modules -maxdepth 1 -mindepth 1 -type d | sed -E s/'^.*\/[0-9\.\-]*\.fc([0-9]+)\..*$'/'\1'/ | sort -uV | tail -n 1)"
    [[ -z ${customIsoLabelShort} ]] && customIsoLabelShort="F${customIsoReleaseVer}-LIVE-CUSTOM"
    
    # add 'liveuser' user without password. Login as liveuser, then run `sudo su` to become root
    systemd-nspawn -D "${customIsoRootfsMountPoint}" adduser -U -G wheel liveuser
    systemd-nspawn -D "${customIsoRootfsMountPoint}" passwd -u -f liveuser
    systemd-nspawn -D "${customIsoRootfsMountPoint}" systemctl enable systemd-networkd
    systemd-nspawn -D "${customIsoRootfsMountPoint}" systemctl disable systemd-networkd-wait-online.service
    systemd-nspawn -D "${customIsoRootfsMountPoint}" systemctl disable NetworkManager-wait-online.service
    systemctl is-enabled systemd-networkd || systemctl enable systemd-networkd --now
    
    # add in repos from host system
    cp -auf /etc/yum.repos.d/* "${customIsoRootfsMountPoint}"/etc/yum.repos.d
    cp -an /etc/pki/rpm-gpg/* "${customIsoRootfsMountPoint}"/etc/pki/rpm-gpg
    
    # if the host kernel is different than the live ISO rootfs's kernel, temporairly make a symlink in the live OS rootfs's /lib/modules directory that goes from host kernel name --> live ISO rootfs kernel name
    [[ "$(find "${customIsoRootfsMountPoint}/lib/modules" -maxdepth 1 -mindepth 1 -type d | sort -uV | tail -n 1)" == "${customIsoRootfsMountPoint}/lib/modules/$(uname -r)" ]] && setupLibModulesSymlinkFlag=false || setupLibModulesSymlinkFlag=true

}

customIso_prepRootfs   
 
customIso_nspawnRootfs() {    
    # # # # # MAKE DESIRED MODIFICATIONS TO LIVE FILESYSTEM ROOTFS HERE # # # # #
    # USE `systemd-nspawn -b -D  "${customIsoRootfsMountPoint}"` TO CUSTOMIZE THE SYSTEM
    # NOTE: you will be prompted to optionally add a networking flag to the above call: '-n' (network-veth) or '--network-interface=<...>' (interface passthrough)
	# NOTE: the '--network-interface=<...>' is the most reliable way to get internet in the container, 
	#       but comes at the expense of losing that iface (and network access through it) everywhere else in the host system. 
    # When done, press `<ctrl>` + `]` 3 times in a row in quick succession to exit the container. When you do this you will be asked if you are done customizing. 
	#       If you say no, you will go back to the start pof this loop and re-select a systremd-nspawn call to use.
  

    # if the host kernel is different than the live ISO rootfs's kernel, temporairly make a symlink in the live OS rootfs's /lib/modules directory that goes from host kernel name --> live ISO rootfs kernel name
    if ${setupLibModulesSymlinkFlag}; then
    	curPWD="$(pwd)"
    	cd "${customIsoRootfsMountPoint}/lib/modules"
    	ln -s "$(find ./ -maxdepth 1 -mindepth 1 -type d | sort -V | tail -n 1 | sed -E s/'^\.\/'//)" "$(uname -r)"
    	cd "${curPWD}"
    	unset curPWD
    fi

    echo -e "\n\n-----------------------------------------------------------------------------\nYou will now customize the rootfs by booting it in a systemd-nspawn container \nAny changes you make here will be present in the final generated ISO image \nLogin as user 'liveuser' (no password), then run 'sudo su' to become root \nTo exit the container, press '<ctrl>' + ']' three times in quick succession \n-----------------------------------------------------------------------------\n\n" >&2
    sleep 5

    # get user input of what networking to set up in nspawn container, then run systemd-nspawn to enter and customize the live image 
    nspawnDoneFlag=false
    until ${nspawnDoneFlag}; do
    	PS3='Select the networking options to use with systemd-nspawn: '
    	select nspawnCmd in "systemd-nspawn -b -D ${customIsoRootfsMountPoint}" "systemd-nspawn -n -b -D ${customIsoRootfsMountPoint}" "systemd-nspawn --network-interface=<...> -b -D ${customIsoRootfsMountPoint}"
    	do
    		echo "You chose ${nspawnCmd}" >&2
    		case $REPLY in
    			
    			1)
    				systemd-nspawn -b -D "${customIsoRootfsMountPoint}"
    				;;
    				
    			2)
    				systemd-nspawn -n -b -D "${customIsoRootfsMountPoint}"
    				;;
    				
    			3)
    				systemd-nspawn -D "${customIsoRootfsMountPoint}" systemctl disable systemd-networkd
    				PS3='Select which network interface to pass to systemd-nspawn: '
    				select nspawnIface in $(ifconfig | grep -E '^[^ \t\n]' | awk -F ':' '{print $1}')
    				do
    					echo "You chose ${nspawnIface}" >&2
    					break
    				done
    				systemd-nspawn --network-interface="${nspawnIface}" -b -D "${customIsoRootfsMountPoint}"
    				systemd-nspawn -D "${customIsoRootfsMountPoint}" systemctl enable systemd-networkd
    				;;
    				
    		esac
    					
    		PS3='SELECT WHETHER TO CONTINUE OR RE-RUN SYSTEMD-NSPAWN: '
    		select nspawnDoneStr in 'IM NOT DONE CUSTOMIZING -- RE-RUN SYSTEMD-NSPAWN' 'IM DONE CUSTOMIZING -- CONTINUE AND GENERATE THE ISO'
    		do	
    			echo "You chose ${nspawnDoneStr}" >&2
    			(( $REPLY == 2 )) && nspawnDoneFlag=true
    			break
    		done
    	break	
    	done
    done
  
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

    # remove temp /lib/modules symlink in live ISO rootfs (if we made this earlier)
    ${setupLibModulesSymlinkFlag} && rm -f "${customIsoRootfsMountPoint}/lib/modules/$(uname -r)"

    # If a new kernel was installed without uninstalling the old kernel, make sure all kernel packages are updated and remove old kernel(s)
    mapfile -t customIsoKernels < <(find "${customIsoRootfsMountPoint}/lib/modules" -maxdepth 1 -mindepth 1 -type d | sed -E s/'^.*\/'// | sort -uVr)
    if (( ${#customIsoKernels[@]} > 1 )); then
    	echo -e '\n\nDETECTED MULTIPLE KERNELS INSTALLED IN THE CUSTOM ISO ROOTFS! \nBelow you will be asked to uninstall all but the newest kernel from the live iso rootfs. \n(a live image having multiple kernels is pretty pointless and perhaps problematic)\n\n' >&2
    	sleep 2
    	dnf --installroot="${customIsoRootfsMountPoint}" --releasever "${customIsoReleaseVer}" update 'kernel*'
    	for nn in ${customIsoKernels[@]:1}; do
			dnf --installroot="${customIsoRootfsMountPoint}" --releasever "${customIsoReleaseVer}" remove 'kernel*'"${nn}"
		done
	fi

}

customIso_nspawnRootfs

getIsoDracutModules() {
	# this helper function querier the dracut modules that dracut in the customized rootfs image knows about, then goes 1-by-1 and checks if the required binaries exist on the rootfs.img system not.
	# this is needed to ensure that livemedia-creator doesnt use a dracut module that it doesnt have the required binaries for, which would cause ISO generation to fail.
	local -a reqAll
	local -a reqAny
	local reqMetFlag
	local dracutMod
	local nn
	local -a customIsoDracutModules

	echo -e "\n\nDetermining which dracut modules the custom ISO is capable of running \n(for each dracut module this checks that all required binaries are present on the system)\n\n" >&2

	mapfile -t customIsoDracutModules < <(ls -1 "${customIsoRootfsMountPoint}"/usr/lib/dracut/modules.d/ | sed -E s/'^[0-9]{2}'//)

	for dracutMod in "${customIsoDracutModules[@]}"; do 
		unset reqAll; unset reqAny; unset reqMetFlag;
		mapfile -t reqAll < <(cat "${customIsoRootfsMountPoint}"/usr/lib/dracut/modules.d/*${dracutMod}/*.sh | grep -F 'require_binaries' | sed -E s/'^.*require_binaries '// | sed -E s/.'((\|\|)|(\;)|(\\)).*$'// | sed -zE s/'[ \t]+'/'\n'/g); 
		mapfile -t reqAny < <(cat "${customIsoRootfsMountPoint}"/usr/lib/dracut/modules.d/*${dracutMod}/*.sh | grep -F 'require_any_binary' |sed -E s/'^.*require_any_binary '// | sed -E s/.'((\|\|)|(\;)|(\\)).*$'// | sed -zE s/'[ \t]+'/'\n'/g);

		reqMetFlag=false
		(( ${#reqAny[@]} == 0 )) && reqMetFlag=true || for nn in "${reqAny[@]##*/}"; do (( $(find "${customIsoRootfsMountPoint}"/usr -type f ! -empty -perm -u+x -perm -g+x -perm -o+x -name "${nn}" | wc -l) > 0 )) && reqMetFlag=true; done
		${reqMetFlag} && (( ${#reqAll[@]} > 0 )) && for nn in "${reqAll[@]##*/}"; do (( $(find "${customIsoRootfsMountPoint}"/usr -type f ! -empty -perm -u+x -perm -g+x -perm -o+x -name "${nn}" | wc -l) == 0 )) && reqMetFlag=false; done
		${reqMetFlag} && echo "${dracutMod}"
	done
}

customIso_setupDracutConf() {
    # if the host kernel is different than the live ISO rootfs's kernel, temporairly make a symlink in the live OS rootfs's /lib/modules directory that goes from host kernel name --> live ISO rootfs kernel name
      if ${setupLibModulesSymlinkFlag}; then
    	curPWD="$(pwd)"
    	cd "${customIsoRootfsMountPoint}/lib/modules"
    	ln -s "$(find ./ -maxdepth 1 -mindepth 1 -type d | sort -V | tail -n 1 | sed -E s/'^\.\/'//)" "$(uname -r)"
    	cd "${curPWD}"
    	unset curPWD
    fi

    # setup a dracut config file on live ISO rootfs for when we call livemedia-creator later
    declare -a dracutAddModules=( bash systemd systemd-ask-password systemd-coredump systemd-initrd systemd-journald systemd-ldconfig systemd-modules-load systemd-rfkill systemd-sysctl systemd-sysext systemd-sysusers systemd-tmpfiles systemd-udevd systemd-veritysetup dbus drm crypt dm dmsquash-live dmsquash-live-ntfs dmsquash-live-autooverlay kernel-modules kernel-modules-extra kernel-network-modules livenet multipath crypt-gpg tpm2-tss iscsi lunmask resume rootfs-block terminfo udev-rules dracut-systemd pollcdrom base fs-lib img-lib shutdown squash uefi-lib convertfs qemu qemu-net biosdevname convertfs rngd terminfo modsign )
	
	# filter down to dracut modules we can actually use
    mapfile -t dracutAddModules < <(printf '%s\n' "${dracutAddModules[@]}" | sort -u | grep -E -f <(printf '^%s$\n' "$(getIsoDracutModules)"))
    
	# add dracut.conf to rootfs.img
    cat > "${customIsoRootfsMountPoint}"/etc/dracut.conf.d/dracut.conf <<EOF
compress=xz
squash_compress=xz
omit_dracutmodules+=" zfs plymouth "
add_dracutmodules+=" ${dracutAddModules[@]} "
hostonly=no
persistent_policy=by-id
install_optional_items+=" /sbin/sysctl /sbin/sysctl "
mdadmconf=no
lvmconf=no
hostonly_cmdline=yes
show_modules=yes
$(${useNvidiaFlag} && echo 'add_drivers+=" nvidia-drm nvidia nvidia-modeset nvidia-peermem nvidia-uvm "' || echo -n '')
EOF
    
    # remove temp /lib/modules symlink in live ISO rootfs (if we made this earlier)
    ${setupLibModulesSymlinkFlag} && rm -f "${customIsoRootfsMountPoint}/lib/modules/$(uname -r)"    
}

customIso_setupDracutConf

customIso_getLorax() {
    # umount modified image
    umount -R "${customIsoRootfsMountPoint}"
    
    # clone lorax git repo
    [[ -d "${customIsoTmpDir}"/lorax ]] && rm -rf "${customIsoTmpDir}"/lorax 
    git clone https://github.com/weldr/lorax.git
    cd "${customIsoTmpDir}"/lorax 
    
    # tweak fedora-livemedia.ks kickstart file slightly then flatten it
    livemediaKS="$(cat "${customIsoTmpDir}"/lorax/docs/fedora-livemedia.ks | sed -E s/'^(part \/ --size)=[0-9]+$'/'\1='"$((( ( ${rootfsSizeGB} * 1024 ) - 502 )))"/ | sed -E s/'^(clearpart .+)$'/'\1 --disklabel=gpt'/ | sed -E s/'(dl.fedoraproject.org\/pub\/fedora\/linux\/development\/)rawhide(\/Everything\/x86_64\/os\/)'/'\1'"${customIsoReleaseVer}"'\2'/)" 
    echo "${livemediaKS}" > "${customIsoTmpDir}"/lorax/docs/fedora-livemedia.ks
    livemediaKS0="${livemediaKS%'%include /tmp/arch-packages.ks'*}"
    livemediaKS0="${livemediaKS0%'%end'*}"
    livemediaKS0="${livemediaKS0#*'%pre'}"
    source <(echo "${livemediaKS0}")
    ksflatten -c "${customIsoTmpDir}/lorax/docs/fedora-livemedia.ks" -o "${customIsoTmpDir}/lorax/docs/fedora-livemedia.ks.flat"
}

customIso_getLorax

customIso_mockBuildAnacondaBootIso() {   
    # build anaconda boot.iso with lorax in mock (setup using the same fedora release version as the custoom ISO image we wanrt to generate)
	
	# tweak mock config to ensure dnf is available
	grep -E "^[ \t]*config_opts\['chroot_setup_cmd'\]" /etc/mock/templates/fedora-branched.tpl | grep -q -E "[ ']dnf[ ']" || sed -i -E s/'^([ \t]*config_opts\['"'"'chroot_setup_cmd'"'"'\].*)'"'"/'\1 dnf'"'"/ /etc/mock/templates/fedora-branched.tpl

	# setup mock
    mock --enable-network -r fedora-${customIsoReleaseVer}-$(uname -m) --init
    mock --enable-network -r fedora-${customIsoReleaseVer}-$(uname -m) --shell -- dnf install 'anaconda*' 'lorax*'
    mock --enable-network -r fedora-${customIsoReleaseVer}-$(uname -m) --shell -- mkdir -p  "${customIsoTmpDir}"
    mkdir -p "/var/lib/mock/fedora-${customIsoReleaseVer}-$(uname -m)/root/${customIsoTmpDir#/}"
	
	# bind-mount $customIsoTmpDir into mock
    mount -o bind "${customIsoTmpDir}" "/var/lib/mock/fedora-${customIsoReleaseVer}-$(uname -m)/root/${customIsoTmpDir#/}"
	
	# build anaconda boot.iso with lorax
    dirAutoRename "/var/lib/mock/fedora-${customIsoReleaseVer}-$(uname -m)/root/${customIsoTmpDir#/}/lorax/anaconda_iso"
	mock --enable-network -r fedora-${customIsoReleaseVer}-$(uname -m) --shell -- PATH="${customIsoTmpDir}/lorax/src/sbin/:${PATH}" PYTHONPATH="${customIsoTmpDir}/lorax/src/" "${customIsoTmpDir}/lorax/src/sbin/lorax" -p Fedora -v "${customIsoReleaseVer}" -r "${customIsoReleaseVer}" -s https://dl.fedoraproject.org/pub/fedora/linux/releases/"${customIsoReleaseVer}"/Everything/x86_64/os/ -s https://dl.fedoraproject.org/pub/fedora/linux/updates/"${customIsoReleaseVer}"/Everything/x86_64/ --sharedir "${customIsoTmpDir}/lorax/share/templates.d/99-generic/" "${customIsoTmpDir}/lorax/anaconda_iso/"
    
    umount "/var/lib/mock/fedora-${customIsoReleaseVer}-$(uname -m)/root/${customIsoTmpDir#/}"
}

customIso_mockBuildAnacondaBootIso

customIso_generateLiveIso() {
    # output dir must be empty or else livemedia-creator complains - rename it if it exists
    dirAutoRename "${customIsoTmpDir}/ISO"
    
    # run livemedia-creator to generate new ISO
    PATH="${customIsoTmpDir}/lorax/src/sbin/:${PATH}" PYTHONPATH="${customIsoTmpDir}"/lorax/src/ "${customIsoTmpDir}"/lorax/src/sbin/livemedia-creator --make-iso --ks="${customIsoTmpDir}/lorax/docs/fedora-livemedia.ks.flat" --fs-image="${customIsoRootfsPath}" --fs-label="${customIsoFsLabel}" --iso-only --iso-name "${customIsoFsLabel}.iso" --iso "${customIsoTmpDir}/lorax/anaconda_iso/images/boot.iso" --lorax-templates="${customIsoTmpDir}/lorax/share/" --resultdir "${customIsoTmpDir}/ISO" --releasever "${customIsoReleaseVer}" --nomacboot --dracut-conf /etc/dracut.conf.d/dracut.conf --extra-boot-args "rd.live.image rd.live.check rd.live.dir=/LiveOS rd.live.squashimg=squashfs.img rd.auto=1 gpt zswap.enabled=1 zswap.compressor=lzo-rle transparent_hugepages=madvise panic=60  mitigations=auto spec_store_bypass_disable=auto noibrs noibpb spectre_v2=auto spectre_v2_user=auto pti=auto retbleed=auto tsx=auto rd.timeout=60 systemd.show_status rd.info rd.udev.info rd.shell selinux=0 $(${useNvidiaFlag} && echo "rd.driver.blacklist=nouveau rd.modprobe.blacklist=nouveau rd.driver.pre=nvidia rd.driver.pre=nvidia_uvm rd.driver.pre=nvidia_drm rd.driver.pre=drm rd.driver.pre=nvidia_modeset driver.blacklist=nouveau modprobe.blacklist=nouveau driver.pre=nvidia driver.pre=nvidia_uvm driver.pre=nvidia_drm driver.pre=drm driver.pre=nvidia_modeset nvidia-drm.modeset=1" || echo -n '')" 
}

customIso_generateLiveIso

customIso_writeLiveUSB() {
    # write iso to usb to finish live image generation
    [[ -n ${customIsoUSBDevPath} ]] && find "${customIsoUSBDevPath}" 1>/dev/null && livecd-iso-to-disk --format --nomac --efi --label "${customIsoLabelShort}" --home-size-mb 4096 --unencrypted-home "$(find "${customIsoTmpDir}/ISO/"{,images}/{boot.iso,"${customIsoFsLabel}.iso"} 2>/dev/null)" "${customIsoUSBDevPath}" 
}

[[ -n ${customIsoUSBDevPath} ]] && find "${customIsoUSBDevPath}" 1>/dev/null && customIso_writeLiveUSB
    

# Run all the functions defined above to generate Iso
