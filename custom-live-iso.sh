#!/usr/bin/bash -x

#https://github.com/jkool702/CustomFedoraLiveISO/blob/main/custom-live-iso.sh

# # # # # # # # # # # # # # SET PARAMETERS  # # # # # # # # # # # # # # # # # 
# all paramaters (except for customIsoUSBDevPath) will be assigned default values or assigned via a user-interactive prompt if left blank

#customIsoReleaseVer=37                            # Fedora release version to use. Default is to try to extract it from the base iso filename.
#customIsoTmpDir=/tmp/customIso                    # main directory where everything is stored. Defaults to /var/tmp (on disk) if you have <32 gb ram, and to /tmp (ramdisk) if you have >= 32 gb ram
#customIsoRootfsDir="${customIsoTmpDir}"/rootfs # where the unsquashed live ISO rootfs.img is stored
#customIsoRootfsMountPoint="${customIsoTmpDir}"/sysroot            # where to mount the live ISO rootfs while you modify it
#customIsoFsLabel='FEDORA-37-KDE-LIVE-CUSTOM'     # filesystem label. Default is "${origIsoFileName%.iso}-CUSTOM"
#customIsoLabelShort='F37-KDE-LIVE'             # short filesystem label
#customIsoUSBDevPath=/dev/sdk                     # dev path for usb to write ISO to. Leave blank to just make the ISO without burning it to a USB
#rootfsSizeGB=64                                 # this is how much space youll have in the live OS. Because this is in a squashfs increasing the free space doesnt really increase the ISO size much. Default is 16 GB.
#useNvidiaFlag=true                               # true/false. this adds stuff to the dracut (drivers + kernel cmdline) to *hopefully* make the nvidia modules load and not the nouveau ones. default depends on if there is any trace on nvidia on the host system.

# TO USE PRE-DOWNLOADED IMAGE, SPECIFY origIsoSource="file://<path>" --OR-- leave origIsoSource blank and place/link the ISO somewhere under $customIsoTmpDir
# if left blank, you will be promoted to choose one of the current fedora "respins" to download OR to choose a local ISO found somewhere under $customIsoTmpDir
#origIsoSource='https://download.fedoraproject.org/pub/fedora/linux/releases/test/39_Beta/Spins/x86_64/iso/Fedora-KDE-Live-x86_64-39_Beta-1.1.iso'
#origIsoSource='https://dl.fedoraproject.org/pub/alt/live-respins/F37-KDE-x86_64-LIVE-20221201.iso'
#origIsoSource='file:///${HOME}/Downloads/Fedora-KDE-Live-x86_64-39-1.5.iso'

# # # # # # # # # # # # # # DEFINE SOME HELPER FUNCTIONS # # # # # # # # # # # # # # # # # 

dirAutoRename() {
    # if the input directory exists, rename it to ${ORIGNAME}_N, where N is the lowest non-negative integer such that ${ORIGNAME}_N doesnt exist
    local dirIn verboseFlag
    local -i kk
    verboseFlag=false
    [[ $1 == '-v' ]] && { verboseFlag=true; shift 1; }
    for dirIn in "${@}"; do
        if [[ -d "${dirIn}" ]] || [[ -f "${dirIn}" ]]; then
            kk=0
            while [[ -d "${dirIn}_${kk}" ]] || [[ -f "${dirIn}_${kk}" ]]; do 
                ((kk++))
            done
            mv "${dirIn}" "${dirIn}_${kk}"
            ${verboseFlag} && echo "${dirIn}_${kk}"
        elif ${verboseFlag}; then
            echo "${dirIn}" 
        fi
    done
}

verifyIsoChecksum() {
    # verifies the sha256 or sha512 hash of the original "base" ISO image file against a known valid file hash
    #
    # USAGE: `isoVerifiedFlag=$(verifyIsoChecksum [file://]${origIsoFilePath})` 
    # 
    # the ISO image file's valid SHA256 or SHA512 has must be in a file at ${origIsoFilePath}.checksum. This file must contain a line consisting of either:
    #      "$fileHash $fileName" or "$fileName $fileHash"
    #
    # NOTE:  if 'file://' is included, it indicates the ISO was sourced locally and not downloaded from the internet
    #        should the valid checksum file be missing or not match the file's actual checksum, this changes the warning message texts accordingly, but otherwise has no effect
    #
    # There are 5 possible function output scenarios
    #     echo {true, false} controls if the script continues or aborts/redownloads the iso
    #     return {0, 1, 2, 3} given info on if the hash matched / didnt match or if the valid hash file couldnt be parsed / wasnt found at ${origIsoFilePath}.checksum
    #
    #     Hashes match                               --> echo true; return 0
    #     Hashes dont match:
    #         User selects continue                  --> echo true; return 1
    #         User chooses to abort/redownload       --> echo false; return 1
    #     Valid hash file exists but cant be parsed  --> echo true; return 2
    #     Valid hash file not found                  --> echo true; return 3
    #
    # NOTE: A missing / unparsable valid hash file will only print a warning to screen. It wont cause the script to stop or to automatically re-download, 
    #       since this could easily result in an infinite download loop if there isn't a valid hash file available in a format this script understands.

    local origIsoFilePath
    local isoValidChecksum
    local isoActualChecksum
    local isoVerifiedFlag
    local localFlag

    echo "${1}" | grep -q -E '^file:\/\/' && localFlag=true || localFlag=false
    origIsoFilePath="${1#file://}"

    if ! [[ -f "${origIsoFilePath}.checksum" ]]; then
        ${localFlag} && echo -e "\nNOTICE: the selected ISO file will not have its checksum verified. \nTo automatically verify the checksum. place a file containing \n\tthe file name and \n\tthe file's SHA256 or SHA512 hash \n\t(both on the same line. seperated by <space>) \nat ${origIsoFilePath}.checksum" >&2 || echo -e "\n\nWARNING: the downloaded ISO image will not have its checksum automatically verified. \n\nAutomatic checksum verification is only available if the online source directory containing the ISO image includes a file named '*CHECKSUM*' (case-insensitive)\nThis *should* be the case for any ISO images downloaded from: https://dl.fedoraproject.org/pub/*, meaning that this ISO image is not coming directly from Fedora. \n\nNOTE: this does not mean that the image is corrupt, just that it will not have its checksum verified to guarantee no corruption.\n\n" >&2 
        sleep 2 && echo 'true' && return 3
    fi

    isoValidChecksum="$(grep -F "${origIsoFilePath##*/}" "${origIsoFilePath}.checksum" | grep -v -E '^#' | sed -E s/'(^|.* )(([0-9a-f]{64})|([0-9a-f]{128}))($| .*)'/'\2'/ | tr -d ' ' | tr -d '\t' | tr -d '\r')"

    if [[ -z ${isoValidChecksum} ]]; then
        echo "WARNING: checksum verification file found but is in an unknown/unsupported format -- could not extract valid checksum from it. ISO image checksum verification will be skipped" >&2 
        sleep 2 && echo 'true' && return 2
    else
        isoActualChecksum="$("sha$((( $(echo -n "${isoValidChecksum}" | wc -c) * 4 )))sum" "${origIsoFilePath}" | awk '{print $1}' | tr -d ' ' | tr -d '\t' | tr -d '\r')"
        if [[ "${isoValidChecksum,,}" == "${isoActualChecksum,,}" ]]; then
            echo "SUCCESS! ISO checksum verified!" >&2
            sleep 2 && echo 'true' && return 0 
        else
            echo "WARNING: the downloaded ISO vailed image checksum verification!" >&2
            PS3='Do you want to CONTINUE and use the (probably corrupted) ISO or '"$(${localFlag} && echo 'ABORT' || echo 'RE-DOWNLOAD it')"'?'
            select userResponse in 'CONTINUE and use the (probably corrupted) ISO' "$(${localFlag} && echo 'ABORT and manually examine/fix the ISO and then re-run this script when ready' || echo 'RE-DOWNLOAD the original base ISO from '"${origIsoSource}"' (note: current downloaded iso and checksum files will be deleted)')"; do
                echo "You chose: ${userResponse}" >&2
                (( ${REPLY} == 1 )) && { echo 'true' && return 1; }
                (( ${REPLY} == 2 )) && { echo 'false' && return 1; }
                break
            done
        fi
    fi
}

getIsoDracutModules() {
    # this helper function querier the dracut modules that dracut in the customized rootfs image knows about, then goes 1-by-1 and checks if the required binaries exist on the rootfs.img system not.
    # this is needed to ensure that livemedia-creator doesnt use a dracut module that it doesnt have the required binaries for, which would cause ISO generation to fail.
    local -a reqAll
    local -a reqAny
    local reqMetFlag
    local dracutMod
    local nn
    local -a customIsoDracutModules
    local customIsoRootfsMountPoint

    customIsoRootfsMountPoint="${1}"

    echo -e "\n\nDetermining which dracut modules the custom ISO is capable of running \n(for each dracut module this checks that all required binaries are present on the system)\n\n" >&2

    mapfile -t customIsoDracutModules < <(find "${customIsoRootfsMountPoint}"/usr/lib/dracut/modules.d/ -mindepth 1 -maxdepth 1 -type d | sed -E s/'^.*\/usr\/lib\/dracut\/modules.d\/'// | sed -E s/'^[0-9]{2}'//)

    for dracutMod in "${customIsoDracutModules[@]}"; do 
        unset reqAll; unset reqAny; unset reqMetFlag;
        mapfile -t reqAll < <(cat "${customIsoRootfsMountPoint}"/usr/lib/dracut/modules.d/*"${dracutMod}"/*.sh | grep -F 'require_binaries' | sed -E s/'^.*require_binaries '// | sed -E s/.'((\|\|)|(\;)|(\\)).*$'// | sed -zE s/'[ \t]+'/'\n'/g); 
        mapfile -t reqAny < <(cat "${customIsoRootfsMountPoint}"/usr/lib/dracut/modules.d/*"${dracutMod}"/*.sh | grep -F 'require_any_binary' |sed -E s/'^.*require_any_binary '// | sed -E s/.'((\|\|)|(\;)|(\\)).*$'// | sed -zE s/'[ \t]+'/'\n'/g);

        reqMetFlag=false
        (( ${#reqAny[@]} == 0 )) && reqMetFlag=true || for nn in "${reqAny[@]##*/}"; do (( $(find "${customIsoRootfsMountPoint}"/usr -type f ! -empty -perm -u+x -perm -g+x -perm -o+x -name "${nn}" | wc -l) > 0 )) && reqMetFlag=true; done
        ${reqMetFlag} && (( ${#reqAll[@]} > 0 )) && for nn in "${reqAll[@]##*/}"; do (( $(find "${customIsoRootfsMountPoint}"/usr -type f ! -empty -perm -u+x -perm -g+x -perm -o+x -name "${nn}" | wc -l) == 0 )) && reqMetFlag=false; done
        ${reqMetFlag} && echo "${dracutMod}"
    done
}

# set umount functioin for trap for cleanup
cleanup_umount() {
    local nn
    mapfile -t umountPaths < <(awk '{print $2}' < /proc/mounts  | grep -F -f <(printf '%s\n' "${customIsoRootfsMountPoint}" "${customIsoTmpDir}"))
    for nn in "${umountPaths[@]}"; do
        sudo umount -R "${nn}"
        grep -q -F "$nn" /proc/mounts && umount -R -f "${nn}" && grep -q -F "$nn" /proc/mounts && umount -R -f -l "${nn}"
    done
    declare -p >"${customIsoTmpDir}"/vars
    exit
}

# # # # # # # # # # # # # # BEGIN SCRIPT # # # # # # # # # # # # # # # # # 

# set selinux to permissive
setenforce 0

# set trap for cleanup
trap cleanup_umount EXIT HUP TERM QUIT ABRT
trap 'printf "%s\n" "" "press [a] to Abort (exit)" "press [u] to Unset INT trap (makes <ctrl> + <c> work normally again)" "press [x] to eXecute a command" "press [p] to print the Present working directory" "press [i] to print Information about what caller/function/line/command is currently running" "press [d] / [D] to start (set -xv) / stop (set +xv) printing Debug output to stderr" "press [v] / [V] to write Vars (declare -p) to [stdout] / to [file (${PWD}/.vars)]" "press [e] / [E] to write Environment (env) to [stdout] / to [file (${PWD}/.env)]" "press anything else to continue" >&2; 
read -r -n 1; 
case "$REPLY" in 
    a) exit ;; 
    u) trap - INT ;; 
    x) if [[ $USER == root ]] && [[ ${SUDO_USER} ]] && ! [[ ${SUDO_USER} == root ]] && type -a su &>/dev/null; then su -p "${SUDO_USER}" < <(read -r && echo "$REPLY"); elif ! [[ $USER == root ]]; then source <(read -r && echo "$REPLY"); else echo "for security running generic commands as root is not allowed" >&2; fi ;; 
    p) echo "$PWD" ;;
    i) echo; [[ $FUNCNAME ]] && printf '"'"'function:  %s\n'"'"' "$FUNCNAME" >&2; printf '"'"'caller  :  %s\n'"'"' "$0" >&2; [[ $BASH_LINENO ]] && printf '"'"'line    :  %s\n'"'"' "${BASH_LINENO}" >&2; printf '"'"'command :  %s\n'"'"' "${BASH_COMMAND}" >&2 ;;
    d) set -xv ;;
    D) set +xv ;;
    v) declare -p ;; 
    V) declare -p >"${PWD}"/.vars ;; 
    e) env ;; 
    E) env >"${PWD}"/.env ;; 
esac' INT

customIso_init() {
    # check inputs and set defaults
    [[ -z ${customIsoTmpDir} ]] && customIsoTmpDir="$( (( $(lsmem | grep 'Total online memory' | awk -F ':' '{print $2}' | sed -E s/'^[ \t]*([0-9]*)G.*$'/'\1'/) < 32 )) && echo '/var')"'/tmp/customIso' 
    customIsoTmpDir="${customIsoTmpDir%/}"
    [[ -z ${customIsoRootfsDir} ]] && customIsoRootfsDir="${customIsoTmpDir}"/rootfs 
    [[ -z ${customIsoRootfsMountPoint} ]] && customIsoRootfsMountPoint="${customIsoTmpDir}"/sysroot
    { [[ -n ${useNvidiaFlag} ]] && { [[ ${useNvidiaFlag} == true ]] || [[ ${useNvidiaFlag} == false ]]; }; } || { { rpm -qa; lshw; } | grep -qi nvidia && useNvidiaFlag=true || useNvidiaFlag=false; } 
    
    customIsoTmpDirRootMnt="$(nn="$customIsoTmpDir"; until findmnt "$nn"; do nn="${nn%/*}"; done | sed -E s/'[ \t]+'/' '/ | cut -f1 -d ' ' | tail -n 1)"

    if findmnt "$customIsoTmpDirRootMnt" | sed -E s/'[ \t]+'/' '/ | cut -f2 -d ' ' | grep -q tmpfs; then

        availMemGB=$(df -h "$customIsoTmpDirRootMnt" | sed -E 's/[ \t]+/ /g;s/^([^ ]* ){3}([^ ]*) .*$/\2/' | grep -oE '[0-9]+')
        totalMemGB=$(df -h "$customIsoTmpDirRootMnt" | sed -E 's/[ \t]+/ /g;s/^([^ ]* ){1}([^ ]*) .*$/\2/' | grep -oE '[0-9]+')
    
        { [[ -n ${rootfsSizeGB} ]] && echo "${rootfsSizeGB}" | grep -q -E '^[0-9]*[1-9]+[0-9]*$'; } || rootfsSizeGB=$(( 7 * availMemGB / 8 ))
        (( ${rootfsSizeGB} > ( 7 * ${availMemGB} / 8 ) )) && sudo mount -o remount,size=$(( ${totalMemGB} + ( 9 * ( ${rootfsSizeGB} - ${availMemGB} ) ) / 8 ))g "$customIsoTmpDirRootMnt"

    else
        { [[ -n ${rootfsSizeGB} ]] && echo "${rootfsSizeGB}" | grep -q -E '^[0-9]*[1-9]+[0-9]*$'; } || rootfsSizeGB=32
    fi

    # Install dependencies. Note: this probably isnt a complete list of all required dependencies. Let me know of any Ive missed and Ill add them.
    sudo dnf --skip-broken install git 'livecd*' 'lorax*' systemd-container lshw wget isomd5sum '*kickstart*' qemu qemu-kvm syslinux systemd-container dracut-live isomd5sum mock coreutils fallocate
    
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
        select origIsoSource in 'SELECT LOCAL ISO (NO DOWNLOAD)' $(wget --spider -r -l 1 --no-parent 'https://dl.fedoraproject.org/pub/alt/live-respins/' 2>&1 | grep -F 'https://dl.fedoraproject.org/pub/alt/live-respins' | sed -E s/'^.*\/'// | grep -E '^F') 
        do
            echo "You Chose: ${origIsoSource}"
            if (( ${REPLY} == 1 )); then
                if [[ -n $(find "${customIsoTmpDir}" -iname '*.iso') ]]; then
                    PS3="Please choose local iso file (found under ${customIsoTmpDir}) to use: "
                    select origIsoSource in 'GO BACK TO PREVIOUS MENU' 'INPUT PATH' $(find "${customIsoTmpDir}" -iname '*.iso' | sed -E s/'^'/'file:\/\/'/)
                    do
                        (( ${REPLY} == 1 )) && origIsoSource=''
                        if (( ${REPLY} == 2 )); then
                        	read -r -e -p 'Please enter the ISO Image path: '
                        	find "${REPLY}" && origIsoSource="file://$(find "${REPLY}")" || { echo "${REPLY} not found. Ensure that you have requisite permissions to access the file. Returning to previous menu" >&2 && origIsoSource=''; }
                        fi
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
    
    echo "The live ISO image will be sourced from ${origIsoSource}" >&2
    
    # get fedora image from internet (using wget) or link from file
    # attempt to automatically verify the image checksum
    origIsoFileName="${origIsoSource##*/}"
    [[ -n ${origIsoFileName} ]] || { echo "ERROR: invalid original ISO source specified. Aborting." >&2 && exit 1; }
    [[ -z ${customIsoFsLabel} ]] && customIsoFsLabel="${origIsoFileName%.iso}-CUSTOM"
    isoVerifiedFlag=false

    if echo "${origIsoSource}" | grep -qE '^file:\/\/'; then
        origIsoFilePath="${origIsoSource#file:\/\/}"

        isoVerifiedFlag=$(verifyIsoChecksum "${origIsoSource}")

        ${isoVerifiedFlag} || exit 1

    else  
        origIsoFilePath="${customIsoTmpDir}/${origIsoFileName}"
        
        until ${isoVerifiedFlag}; do
            echo "Now Downloading ISO image and (if available) checksums from ${origIsoSource}" >&2
            wget --output-document="${origIsoFilePath}" "${origIsoSource}"
            
            mapfile -t availIsoChecksums < <(wget --spider -r -l 1 --no-parent "${origIsoSource%/*}" 2>&1 | grep -F "${origIsoSource%/*}" | awk '{print $3}' | grep -i checksum | sort -u)
            (( ${#availIsoChecksums[@]} > 0 )) && wget --output-document="${origIsoFilePath}.checksum" "${availIsoChecksums[@]}"
            
            isoVerifiedFlag=$(verifyIsoChecksum "${origIsoFilePath}")
            ${isoVerifiedFlag} || rm -f "${origIsoFilePath}" "${origIsoFilePath}.checksum"
        done   
    fi      
}

customIso_getOrigIso   

customIso_prepRootfs() {   
    # mount original iso image
    sudo mount "${origIsoFilePath}" "${customIsoTmpDir}"/mnt/iso_old
    
    # unsquash root filesystem
    sudo unsquashfs -d "${customIsoRootfsDir}" -f -x "$(find "${customIsoTmpDir}"/mnt/iso_old/ -type f -name 'squashfs.img')"
    customIsoRootfsPath="$(find "${customIsoRootfsDir}" -type f -name 'rootfs.img')"
    
    rootfsOrigSize=$(du "${customIsoRootfsPath}" --bytes | awk '{print $1}')

    # zero-pad image to ${rootfsSizeGB} GiB
    dd if=/dev/zero count=$(( ( ( ${rootfsSizeGB} * ( 2 ** 30 ) )  - ${rootfsOrigSize} ) / ( 2  ** 20 ) )) bs=$(( 2 ** 20 )) >> "${customIsoRootfsPath}"
    dd if=/dev/zero bs=$(( ( ${rootfsSizeGB} * ( 2 ** 30 ) )  - $(du "${customIsoRootfsPath}" --bytes | awk '{print $1}') )) count=1 >> "${customIsoRootfsPath}"

    fallocate -p -o ${rootfsOrigSize} -l $(( $(du "${customIsoRootfsPath}" --bytes | awk '{print $1}')  - ${rootfsOrigSize} )) "${customIsoRootfsPath}"
    
    sudo umount -R "${customIsoRootfsMountPoint}"
    sudo umount -R "${customIsoRootfsPath}"

    # extend ext4 filesystem 
    e2fsck -f -p "${customIsoRootfsPath}"
    resize2fs "${customIsoRootfsPath}" -b
    resize2fs "${customIsoRootfsPath}"
    
    # umount orig iso and mount unsquashed rootfs
    sudo umount "${customIsoTmpDir}"/mnt/iso_old
    sudo mount "${customIsoRootfsPath}" "${customIsoRootfsMountPoint}"

    # 
    
    # extract Fedora version from rootfs
    { [[ -n ${customIsoReleaseVer} ]] && echo "${customIsoReleaseVer}" | grep -q -E '^[0-9]*[1-9]+[0-9]*$'; } || customIsoReleaseVer="$(find "${customIsoRootfsMountPoint}"/lib/modules -maxdepth 1 -mindepth 1 -type d | sed -E s/'^.*\/[0-9\.\-]*\.fc([0-9]+)\..*$'/'\1'/ | sort -uV | tail -n 1)"
    [[ -z ${customIsoLabelShort} ]] && customIsoLabelShort="F${customIsoReleaseVer}-LIVE-CUSTOM"
    
    # add 'liveuser' user without password. Login as liveuser, then run `sudo su` to become root
    #systemd-nspawn -D "${customIsoRootfsMountPoint}" adduser -U -G wheel liveuser
    #systemd-nspawn -D "${customIsoRootfsMountPoint}" passwd -u -f liveuser
    #systemd-nspawn -D "${customIsoRootfsMountPoint}" systemctl enable systemd-networkd
    #systemd-nspawn -D "${customIsoRootfsMountPoint}" systemctl disable systemd-networkd-wait-online.service
    #systemd-nspawn -D "${customIsoRootfsMountPoint}" systemctl disable NetworkManager-wait-online.service
    sudo systemd-nspawn -D "${customIsoRootfsMountPoint}" -- /usr/bin/bash -c 'cat /etc/passwd | grep -qE ^liveuser && userdel liveuser; cat /etc/group | grep -qE ^liveuser && groupdel liveuser; useradd -e "-1" -f "-1" -G wheel -s /usr/bin/bash -p "" -u 1000 -m -U liveuser; passwd -d -f liveuser; passwd -u -f liveuser; passwd -x "-1" liveuser; usermod -U liveuser; systemctl enable systemd-networkd; systemctl disable systemd-networkd-wait-online.service; systemctl disable NetworkManager-wait-online.service'
    systemctl is-enabled systemd-networkd || sudo systemctl enable systemd-networkd --now
    
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
            echo "You Chose: ${nspawnCmd}" >&2
            case $REPLY in
                
                1)
                    sudo systemd-nspawn -b -D "${customIsoRootfsMountPoint}"
                    ;;
                    
                2)
                    sudo systemd-nspawn -n -b -D "${customIsoRootfsMountPoint}"
                    ;;
                    
                3)
                    sudo systemd-nspawn -D "${customIsoRootfsMountPoint}" systemctl disable systemd-networkd
                    PS3='Select which network interface to pass to systemd-nspawn: '
                    select nspawnIface in $(ifconfig | grep -E '^[^ \t\n]' | awk -F ':' '{print $1}')
                    do
                        echo "You Chose: ${nspawnIface}" >&2
                        break
                    done
                    sudo systemd-nspawn --network-interface="${nspawnIface}" -b -D "${customIsoRootfsMountPoint}"
                    sudo systemd-nspawn -D "${customIsoRootfsMountPoint}" systemctl enable systemd-networkd
                    sudo systemd-nspawn -D "${customIsoRootfsMountPoint}" systemctl disable systemd-networkd-wait-online.service
                    ;;
                    
            esac
                        
            PS3='SELECT WHETHER TO CONTINUE OR RE-RUN SYSTEMD-NSPAWN: '
            select nspawnDoneStr in 'IM NOT DONE CUSTOMIZING -- RE-RUN SYSTEMD-NSPAWN' 'IM DONE CUSTOMIZING -- CONTINUE AND GENERATE THE ISO'
            do    
                echo "You Chose: ${nspawnDoneStr}" >&2
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
        sudo dnf --installroot="${customIsoRootfsMountPoint}" --releasever "${customIsoReleaseVer}" -y update 'kernel*'
        for nn in "${customIsoKernels[@]:1}"; do
            sudo dnf --installroot="${customIsoRootfsMountPoint}" --releasever "${customIsoReleaseVer}" -y remove 'kernel*'"${nn}"
        done
    fi
}

customIso_nspawnRootfs

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
    mapfile -t dracutAddModules < <(printf '%s\n' "${dracutAddModules[@]}" | sort -u | grep -E -f <(printf '^%s$\n' "$(getIsoDracutModules "${customIsoRootfsMountPoint}")"))
    
    # add dracut.conf to rootfs.img
    cat > "${customIsoRootfsMountPoint}"/etc/dracut.conf.d/dracut-customLiveIso.conf <<EOF
compress=xz
squash_compress=xz
omit_dracutmodules+=" zfs plymouth "
add_dracutmodules+=" ${dracutAddModules[@]} "
hostonly=no
persistent_policy=by-id
install_optional_items+=" /sbin/sysctl /sbin/sysctl /bin/ntfs-3g /bin/ntfs-3g "
mdadmconf=no
lvmconf=no
hostonly_cmdline=yes
show_modules=yes
$(${useNvidiaFlag} && echo 'add_drivers+=" nvidia-drm nvidia nvidia-modeset nvidia-peermem nvidia-uvm ntfs3 "' || echo 'add_drivers+=" ntfs3 "')
EOF

    # copy to host system
    dirAutoRename /etc/dracut.conf.d/dracut-customLiveIso.conf
    \cp -f "${customIsoRootfsMountPoint}"/etc/dracut.conf.d/dracut-customLiveIso.conf /etc/dracut.conf.d/dracut-customLiveIso.conf
    
    # remove temp /lib/modules symlink in live ISO rootfs (if we made this earlier)
    ${setupLibModulesSymlinkFlag} && rm -f "${customIsoRootfsMountPoint}/lib/modules/$(uname -r)"    
    
    # make sure that user 'liveuser' is still valid  and active and passwordless, and that network-wait-online services are still disabled.
    sudo systemd-nspawn -D "${customIsoRootfsMountPoint}" -- /usr/bin/bash -c 'usermod -a -G wheel liveuser; usermod -e "-1" -f "-1" -s /usr/bin/bash -p "" liveuser; passwd -d -f liveuser; passwd -u -f liveuser; passwd -x "-1" liveuser; usermod -U liveuser; systemctl disable systemd-networkd-wait-online.service; systemctl disable NetworkManager-wait-online.service'
    
    # umount modified image
    sudo umount -R "${customIsoRootfsMountPoint}"
}

customIso_setupDracutConf

customIso_getLorax() {
    
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
    sudo mock --enable-network -r fedora-${customIsoReleaseVer}-$(uname -m) --init
    sudo mock --enable-network -r fedora-${customIsoReleaseVer}-$(uname -m) --shell -- dnf install 'anaconda*' 'lorax*'
    sudo mock --enable-network -r fedora-${customIsoReleaseVer}-$(uname -m) --shell -- mkdir -p "${customIsoTmpDir}"
    mkdir -p "/var/lib/mock/fedora-${customIsoReleaseVer}-$(uname -m)/root/${customIsoTmpDir#/}"
    
    # bind-mount $customIsoTmpDir into mock
    sudo mount -o bind "${customIsoTmpDir}" "/var/lib/mock/fedora-${customIsoReleaseVer}-$(uname -m)/root/${customIsoTmpDir#/}"
    
    # build anaconda boot.iso with lorax
    dirAutoRename "/var/lib/mock/fedora-${customIsoReleaseVer}-$(uname -m)/root/${customIsoTmpDir#/}/lorax/anaconda_iso"
 
     if curl https://dl.fedoraproject.org/pub/fedora/linux/development/39/Everything/x86_64/os/repodata/repomd.xml 2>/dev/null | grep -q '404 Not Found'; then
        sudo mock --enable-network -r fedora-${customIsoReleaseVer}-$(uname -m) --shell -- PATH="${customIsoTmpDir}/lorax/src/sbin/:${PATH}" PYTHONPATH="${customIsoTmpDir}/lorax/src/" "${customIsoTmpDir}/lorax/src/sbin/lorax" -p Fedora -v "${customIsoReleaseVer}" -r "${customIsoReleaseVer}" -s https://dl.fedoraproject.org/pub/fedora/linux/updates/"${customIsoReleaseVer}"/Everything/x86_64/ --sharedir "${customIsoTmpDir}/lorax/share/templates.d/99-generic/" "${customIsoTmpDir}/lorax/anaconda_iso/"
    else
        sudo mock --enable-network -r fedora-${customIsoReleaseVer}-$(uname -m) --shell -- PATH="${customIsoTmpDir}/lorax/src/sbin/:${PATH}" PYTHONPATH="${customIsoTmpDir}/lorax/src/" "${customIsoTmpDir}/lorax/src/sbin/lorax" -p Fedora -v "${customIsoReleaseVer}" -r "${customIsoReleaseVer}" -s https://dl.fedoraproject.org/pub/fedora/linux/updates/"${customIsoReleaseVer}"/Everything/x86_64/ -s https://dl.fedoraproject.org/pub/fedora/linux/development/"${customIsoReleaseVer}"/Everything/x86_64/os/ --sharedir "${customIsoTmpDir}/lorax/share/templates.d/99-generic/" "${customIsoTmpDir}/lorax/anaconda_iso/"
    fi
    
    sudo umount "/var/lib/mock/fedora-${customIsoReleaseVer}-$(uname -m)/root/${customIsoTmpDir#/}"
}

customIso_mockBuildAnacondaBootIso

customIso_generateLiveIso() {
    # output dir must be empty or else livemedia-creator complains - rename it if it exists
    dirAutoRename "${customIsoTmpDir}/ISO"

    mkdir -p "${customIsoTmpDir}"/tmp
    
    # run livemedia-creator to generate new ISO
    PATH="${customIsoTmpDir}/lorax/src/sbin/:${PATH}" PYTHONPATH="${customIsoTmpDir}"/lorax/src/ ""${customIsoTmpDir}"/lorax/src/sbin/livemedia-creator" --make-iso --ks="${customIsoTmpDir}/lorax/docs/fedora-livemedia.ks.flat" --fs-image="${customIsoRootfsPath}" --fs-label="${customIsoFsLabel}" --iso-only --iso-name "${customIsoFsLabel}.iso" --iso "${customIsoTmpDir}/lorax/anaconda_iso/images/boot.iso" --lorax-templates="${customIsoTmpDir}/lorax/share/" --resultdir "${customIsoTmpDir}/ISO" --releasever "${customIsoReleaseVer}" --nomacboot --dracut-conf /etc/dracut.conf.d/dracut-customLiveIso.conf --tmp "${customIsoTmpDir}"/tmp --extra-boot-args "rd.live.image rd.live.check rd.live.dir=/LiveOS rd.live.squashimg=squashfs.img rd.auto=1 gpt zswap.enabled=1 zswap.compressor=lzo-rle transparent_hugepages=madvise panic=60  mitigations=auto spec_store_bypass_disable=auto noibrs noibpb spectre_v2=auto spectre_v2_user=auto pti=auto retbleed=auto tsx=auto rd.timeout=60 systemd.show_status rd.info rd.udev.log-priority=info rd.shell selinux=0 $(${useNvidiaFlag} && echo "rd.driver.blacklist=nouveau rd.modprobe.blacklist=nouveau rd.driver.pre=nvidia rd.driver.pre=nvidia_uvm rd.driver.pre=nvidia_drm rd.driver.pre=drm rd.driver.pre=nvidia_modeset driver.blacklist=nouveau modprobe.blacklist=nouveau driver.pre=nvidia driver.pre=nvidia_uvm driver.pre=nvidia_drm driver.pre=drm driver.pre=nvidia_modeset nvidia-drm.modeset=1" || echo -n '')" 
}

customIso_generateLiveIso

customIso_writeLiveUSB() {
    # write iso to usb to finish live image generation
    [[ -n ${customIsoUSBDevPath} ]] && find "${customIsoUSBDevPath}" 1>/dev/null && livecd-iso-to-disk --format --nomac --efi --label "${customIsoLabelShort}" --home-size-mb 4096 --unencrypted-home "$(find "${customIsoTmpDir}/ISO/"{,images}/{boot.iso,"${customIsoFsLabel}.iso"} 2>/dev/null)" "${customIsoUSBDevPath}" 
}

[[ -n ${customIsoUSBDevPath} ]] && find "${customIsoUSBDevPath}" 1>/dev/null && customIso_writeLiveUSB
    

# Run all the functions defined above to generate Iso
