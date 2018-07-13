#!/bin/bash

disable_cramfs () {
	echo -e "\e[92m== 1.1.1.1 Ensure mounting of cramfs filesystems is disabled ==\e\n"
	if [[ "$(modprobe -n -v cramfs 2>/dev/null)" = *install* ]]
		then echo "Passed!"
	else
		echo -e "\e[31mFailed!\e[0m : \nVerify output of 'modprobe -n -v cramfs' command.  Should show this output: \n
		# modprobe -n -v cramfs
		install /bin/true\n
		Resolve by using this command:\n
		echo 'install cramfs /bin/true' >> /etc/modprobe.d/CIS.conf"
	fi

	lsmod_cramfs=`lsmod | grep cramfs`
	if [ "$lsmod_cramfs" = "" ]
		then echo ""
	else
		echo -e "\e[31mFailed!\e[0m : \nVerify output of 'lsmod | grep cramfs'.  Output should be blank. \n"
        fi


}

disable_freevxfs () {
        echo -e "\e[92m== 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled ==\e\n"
        if [[ "$(modprobe -n -v freevxfs 2>/dev/null)" = *install* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'modprobe -n -v freevxfs' command.  Should show this output: \n
                # modprobe -n -v freevxfs
                install /bin/true\n
                Resolve by using this command:\n
                echo 'install freevxfs /bin/true' >> /etc/modprobe.d/CIS.conf"
        fi

        lsmod_freevxfs=`lsmod | grep freevxfs`
        if [ "$lsmod_freevxfs" = "" ]
                then echo ""
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'lsmod | grep freevxfs'.  Output should be blank. "
        fi


}

disable_jffs2 () {
        echo -e "\e[92m== 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled ==\e\n"
        if [[ "$(modprobe -n -v jffs2 2>/dev/null)" = *install* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'modprobe -n -v jffs2' command.  Should show this output: \n
                # modprobe -n -v jffs2
                install /bin/true\n
                Resolve by using this command:\n
                echo 'install jffs2 /bin/true' >> /etc/modprobe.d/CIS.conf"
        fi

        lsmod_jffs2=`lsmod | grep jffs2`
        if [ "$lsmod_jffs2" = "" ]
                then echo ""
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'lsmod | grep jffs2'.  Output should be blank. "
        fi


}

disable_hfs () {
        echo -e "\e[92m== 1.1.1.4 Ensure mounting of hfs filesystems is disabled ==\e\n"
        if [[ "$(modprobe -n -v hfs 2>/dev/null)" = *install* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'modprobe -n -v hfs' command.  Should show this output: \n
                # modprobe -n -v hfs
                install /bin/true\n
                Resolve by using this command:\n
                echo 'install hfs /bin/true' >> /etc/modprobe.d/CIS.conf\n"
        fi

        lsmod_hfs=`lsmod | grep hfs`
        if [ "$lsmod_hfs" = "" ]
                then echo ""
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'lsmod | grep hfs'.  Output should be blank. \n"
        fi


}

disable_hfsplus () {
        echo -e "\e[92m== 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled ==\e\n"
        if [[ "$(modprobe -n -v hfsplus 2>/dev/null)" = *install* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'modprobe -n -v hfsplus' command.  Should show this output: \n
                # modprobe -n -v hfsplus
                install /bin/true\n
                Resolve by using this command:\n
                echo 'install hfsplus /bin/true' >> /etc/modprobe.d/CIS.conf"
        fi

        lsmod_hfsplus=`lsmod | grep hfsplus`
        if [ "$lsmod_hfsplus" = "" ]
                then echo ""
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'lsmod | grep hfsplus'.  Output should be blank. \n"
        fi


}

disable_squashfs () {
        echo -e "\e[92m== 1.1.1.6 Ensure mounting of squashfs filesystems is disabled ==\e\n"
        if [[ "$(grep squashfs /etc/modprobe.d/CIS.conf 2>/dev/null)" = *install* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'modprobe -n -v squashfs' command.  Should show this output: \n
                # modprobe -n -v squashfs
                install /bin/true\n
                Resolve by using this command:\n
                echo 'install squashfs /bin/true' >> /etc/modprobe.d/CIS.conf"
        fi

        lsmod_squashfs=`lsmod | grep squashfs`
        if [ "$lsmod_squashfs" = "" ]
                then echo ""
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'lsmod | grep squashfs'.  Output should be blank. "
        fi


}

disable_udf () {
        echo -e "\e[92m== 1.1.1.7 Ensure mounting of udf filesystems is disabled ==\e\n"
        if [[ "$(modprobe -n -v udf 2>/dev/null)" = *install* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'modprobe -n -v udf' command.  Should show this output: \n
                # modprobe -n -v udf
                install /bin/true\n
                Resolve by using this command:\n
                echo 'install udf /bin/true' >> /etc/modprobe.d/CIS.conf"
        fi

        lsmod_udf=`lsmod | grep udf`
        if [ "$lsmod_udf" = "" ]
                then echo ""
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'lsmod | grep udf'.  Output should be blank. "
        fi


}

disable_fat () {
        echo -e "\e[92m== 1.1.1.8 Ensure mounting of fat filesystems is disabled ==\e\n"
        if [[ "$(grep vfat /etc/modprobe.d/CIS.conf 2>/dev/null)" = *install* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'modprobe -n -v vfat' command.  Should show this output: \n
                # modprobe -n -v vfat
                install /bin/true\n
                Resolve by using this command:\n
                echo 'install vfat /bin/true' >> /etc/modprobe.d/CIS.conf"
        fi

        lsmod_vfat=`lsmod | grep vfat`
        if [ "$lsmod_vfat" = "" ]
                then echo ""
        else
                echo -e "\e[31mFailed!\e[0m : \nVerify output of 'lsmod | grep vfat'.  Output should be blank. "
        fi


}

tmp_on_own_partition () {
        echo -e "\e[92m== 1.1.2 Ensure separate partition exists for /tmp  ==\e\n"
	if [[ "$(mount | grep /tmp)" = *on./tmp.type* ]]
		then echo "Passed!"
	else
		echo -e "\e[31mFailed!\e[0m : \n		Audit: Run the following command and verify output shows /tmp is mounted: \n
		# mount | grep /tmp
		tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)\n
		Remediation:
		For new installations, during installation create a custom partition setup and specify a separate partition for /tmp.
		For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.\n
		Notes:
		systemd includes the tmp.mount service which should be used instead of configuring /etc/fstab.\n"
	fi

}

tmp_nodev () {
        echo -e "\e[92m== 1.1.3 Ensure nodev option set on /tmp partition ==\e\n"
	if [[ "$(mount | grep /tmp)" = *on./tmp.type.+?nodev.* ]]
		then echo "Passed!"
	else
		echo -e "\e[31mFailed!\e[0m : \n		Audit: If a /tmp partition exists run the following command and verify that the nodev option is set on /tmp:\n
		# mount | grep /tmp
		tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)\n
		Remediation:
		Edit the /etc/fstab file and add nodev to the fourth field (mounting options) for the /tmp partition. See the fstab(5) manual page for more information.
		Run the following command to remount /tmp: # mount -o remount,nodev /tmp\n
		Notes:
		systemd includes the tmp.mount service which should be used instead of configuring /etc/fstab. Mounting options are configured in the Options setting in /etc/systemd/system/tmp.mount.\n"
	fi
}

tmp_nosuid () {
        echo -e "\e[92m== 1.1.4 Ensure nosuid option set on /tmp partition ==\e\n"
        if [[ "$(mount | grep /tmp)" = */tmp.type.+?nosuid.* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n		Audit:
		If a /tmp partition exists run the following command and verify that the nosuid option is set on /tmp:\n
		# mount | grep /tmp
		tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)\n
		Remediation:
		Edit the /etc/fstab file and add nosuid to the fourth field (mounting options) for the /tmp partition. See the fstab(5) manual page for more information.\n
		Run the following command to remount /tmp: # mount -o remount,nosuid /tmp\n
		Notes:
		systemd includes the tmp.mount service which should be used instead of configuring /etc/fstab. Mounting options are configured in the Options setting in /etc/systemd/system/tmp.mount.\n"
	fi
}

var_on_own_partition () {
        echo -e "\e[92m== 1.1.5 Ensure separate partition exists for /var  ==\e\n"
        if [[ "$(mount | grep /var)" = */var.type* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit: Run the following command and verify output shows /var is mounted: \n
		# mount | grep /var
		/dev/xvdg1 on /var type ext4 (rw,relatime,data=ordered)\n
                Remediation:
                For new installations, during installation create a custom partition setup and specify a separate partition for /var.
		For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.\n"
        fi

}

var_tmp_on_own_partition () {
        echo -e "\e[92m== 1.1.6 Ensure separate partition exists for /var/tmp  ==\e\n"
        if [[ "$(mount | grep /var/tmp)" = */var/tmp.type* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit: Run the following command and verify output shows /var/tmp is mounted: \n
                # mount | grep /var/tmp
		tmpfs on /var/tmp type ext4 (rw,nosuid,nodev,noexec,relatime)\n
                Remediation:
	        For new installations, during installation create a custom partition setup and specify a separate partition for /var/tmp.
		For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.\n"
	fi

}

var_tmp_nodev () {
        echo -e "\e[92m== 1.1.7 Ensure nodev option set on /var/tmp partition ==\e\n"
        if [[ "$(mount | grep /var/tmp)" = *on./var/tmp.type.+?nodev.* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit: If a /var/tmp partition exists run the following command and verify that the nodev option is set on /var/tmp:\n
		# mount | grep /var/tmp
		tmpfs on /var/tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)\n
		Remediation:
                Edit the /etc/fstab file and add nodev to the fourth field (mounting options) for the /var/tmp partition. See the fstab(5) manual page for more information.
                Run the following command to remount /var/tmp: # mount -o remount,nodev /var/tmp\n"
        fi
}

var_tmp_nosuid () {
        echo -e "\e[92m== 1.1.8 Ensure nosuid option set on /var/tmp partition ==\e\n"
        if [[ "$(mount | grep /var/tmp)" = */var/tmp.type.+?nosuid.* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                If a /var/tmp partition exists run the following command and verify that the nosuid option is set on /var/tmp:\n
                # mount | grep /var/tmp
                tmpfs on /var/tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)\n
                Remediation:
                Edit the /etc/fstab file and add nosuid to the fourth field (mounting options) for the /var/tmp partition. See the fstab(5) manual page for more information.\n
                Run the following command to remount /var/tmp: # mount -o remount,nosuid /var/tmp\n"
        fi
}

var_tmp_noexec () {
        echo -e "\e[92m== 1.1.9 Ensure noexec option set on /var/tmp partition ==\e\n"
        if [[ "$(mount | grep /var/tmp)" = */var/tmp.type.+?noexec.* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                If a /var/tmp partition exists run the following command and verify that the noexec option is set on /var/tmp:\n
                # mount | grep /var/tmp
                tmpfs on /var/tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)\n
                Remediation:
                Edit the /etc/fstab file and add noexec to the fourth field (mounting options) for the /var/tmp partition. See the fstab(5) manual page for more information.\n
                Run the following command to remount /var/tmp: # mount -o remount,noexec /var/tmp\n"
        fi
}

var_log_on_own_partition () {
        echo -e "\e[92m== 1.1.10 Ensure separate partition exists for /var/log  ==\e\n"
        if [[ "$(mount | grep /var/log)" = */var/log.type* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit: Run the following command and verify output shows /var/log is mounted: \n
                # mount | grep /var/log
                /dev/xvdg1 on /var/log type ext4 (rw,relatime,data=ordered)\n
                Remediation:
                For new installations, during installation create a custom partition setup and specify a separate partition for /var/log.
                For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.\n"
        fi

}

var_log_audit_on_own_partition () {
        echo -e "\e[92m== 1.1.11 Ensure separate partition exists for /var/log/audit  ==\e\n"
        if [[ "$(mount | grep /var/log/audit)" = */var/log/audit.type* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit: Run the following command and verify output shows /var/log/audit is mounted: \n
                # mount | grep /var/log/audit
                /dev/xvdg1 on /var/log/audit type ext4 (rw,relatime,data=ordered)\n
                Remediation:
                For new installations, during installation create a custom partition setup and specify a separate partition for /var/log/audit.
                For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.\n"
        fi

}

home_on_own_partition () {
        echo -e "\e[92m== 1.1.12 Ensure separate partition exists for /home  ==\e\n"
        if [[ "$(mount | grep /home)" = */home.type* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit: Run the following command and verify output shows /home is mounted: \n
                # mount | grep /home
                /dev/xvdg1 on /home type ext4 (rw,relatime,data=ordered)\n
                Remediation:
                For new installations, during installation create a custom partition setup and specify a separate partition for /home.
                For systems that were previously installed, create a new partition and configure /etc/fstab as appropriate.\n"
        fi

}

home_nodev () {
        echo -e "\e[92m== 1.1.13 Ensure nodev option set on /home partition ==\e\n"
        if [[ "$(mount | grep /home)" = *on./home.type.+?nodev.* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit: If a /home partition exists run the following command and verify that the nodev option is set on /home:\n
                # mount | grep /home
                /dev/xvdf1  on /home type tmpfs (rw,nosuid,nodev,noexec,relatime)\n
                Remediation:
                Edit the /etc/fstab file and add nodev to the fourth field (mounting options) for the /home partition. See the fstab(5) manual page for more information.
                Run the following command to remount /home: # mount -o remount,nodev /home\n"
        fi
}

dev_shm_nodev () {
        echo -e "\e[92m== 1.1.14 Ensure nodev option set on /dev/shm partition ==\e\n"
        if [[ "$(mount | grep /dev/shm)" = *on./dev/shm.type.+?nodev.* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit: If a /dev/shm partition exists run the following command and verify that the nodev option is set on /dev/shm:\n
                # mount | grep /dev/shm
                tmpfs  on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime)\n
                Remediation:
                Edit the /etc/fstab file and add nodev to the fourth field (mounting options) for the /dev/shm partition. See the fstab(5) manual page for more information.
                Run the following command to remount /dev/shm: # mount -o remount,nodev /dev/shm\n"
        fi
}

dev_shm_nosuid () {
        echo -e "\e[92m== 1.1.15 Ensure nosuid option set on /dev/shm partition ==\e\n"
        if [[ "$(mount | grep /dev/shm)" = */dev/shm.type.+?nosuid.* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                If a /dev/shm partition exists run the following command and verify that the nosuid option is set on /dev/shm:\n
                # mount | grep /dev/shm
                tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime)\n
                Remediation:
                Edit the /etc/fstab file and add nosuid to the fourth field (mounting options) for the /dev/shm partition. See the fstab(5) manual page for more information.\n
                Run the following command to remount /dev/shm: # mount -o remount,nosuid /dev/shm\n"
        fi
}

dev_shm_noexec () {
        echo -e "\e[92m== 1.1.16 Ensure noexec option set on /dev/shm partition ==\e\n"
        if [[ "$(mount | grep /dev/shm)" = */dev/shm.type.+?noexec.* ]]
                then echo "Passed!"
        else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                If a /dev/shm partition exists run the following command and verify that the noexec option is set on /dev/shm:\n
                # mount | grep /dev/shm
                tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime)\n
                Remediation:
                Edit the /etc/fstab file and add noexec to the fourth field (mounting options) for the /dev/shm partition. See the fstab(5) manual page for more information.\n
                Run the following command to remount /dev/shm: # mount -o remount,noexec /dev/shm\n"
        fi
}

removable_media_nodev () {
        echo -e "\e[92m== 1.1.17 Ensure nodev option set on removable media partitions (Not Scored) ==\e\n"
                echo -e "\e[31mCHECK THIS MANUALLY USING THE 'mount' COMMAND.  REMOVABLE MEDIA CAN HAVE DIFFERING MOUNT POINTS\e\n"
}

removable_media_nosuid () {
        echo -e "\e[92m== 1.1.18 Ensure nosuid option set on removable media partitions (Not Scored) ==\e\n"
                echo -e "\e[31mCHECK THIS MANUALLY USING THE 'mount' COMMAND.  REMOVABLE MEDIA CAN HAVE DIFFERING MOUNT POINTS\e\n"
}

removable_media_noexec () {
        echo -e "\e[92m== 1.1.19 Ensure noexec option set on removable media partitions (Not Scored) ==\e\n"
                echo -e "\e[31mCHECK THIS MANUALLY USING THE 'mount' COMMAND.  REMOVABLE MEDIA CAN HAVE DIFFERING MOUNT POINTS\e\n"
}

sticky_bit_set_on_world_writable_directories () {
	echo -e "\e[92m== 1.1.20 Ensure sticky bit is set on all world-writable directories ==\e\n"
	if [[ "$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null)" = "" ]]
		then echo -e "Passed!\n"
	else
	        echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify no world writable directories exist without the sticky bit set:\n
		# df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
		No output should be returned\n
		Remediation:\n
		Run the following command to set the sticky bit on all world writable directories:\n
		# df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t\n"
	fi
}

disable_automounting () {
	echo -e "\e[92m== 1.1.21 Disable Automounting ==\e\n"
	if [[ "$(systemctl is-enabled autofs 2> /dev/null)" = "enabled" ]]
		then echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify autofs is not enabled:\n
		# systemctl is-enabled autofs\n
		Verify result is not 'enabled'.\n
		Remediation:\n
		Run the following command to disable autofs:\n
		systemctl disable autofs\n"
	else
		echo -e "Passed!\n"
	fi
}

ensure_package_manager_repos_are_configured () {
	echo -e "\e[92m== 1.2.1 Ensure package manager repositories are configured (Not Scored) ==\e\n"
	echo -e "\e[31mVerify that the package repositories are configured correctly from the following output:\n"
apt-cache policy
	echo -e "\n\e[92mRemediation:\n
Configure your package manager repositories according to site policy.\n"
}

ensure_gpg_keys_are_configured () {
        echo -e "\e[92m== 1.2.2 Ensure Ensure GPG keys are configured (Not Scored) ==\e\n"
        echo -e "\e[31mVerify that GPG keys are configured correctly for your pacakge manager from the output below:\n"
apt-key list
        echo -e "\n\e[92mRemediation:\n
Update your package manager GPG keys in accordance with site policy.\n"
}

ensure_aide_is_installed () {
        echo -e "\e[92m== 1.3.1 Ensure AIDE is installed ==\e\n"
	if [[ "$(dpkg -s aide 2> /dev/null| grep Status)" = "Status: install ok installed" ]]
		then echo -e "Passed!\n"
	else
		echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify AIDE is installed:\n
		# dpkg -s aide\n
		Remediation:\n
		Run the following command to install AIDE:\n
		# apt-get install aide\n
		Configure AIDE as appropriate for your environment. Consult the AIDE documentation for options.\n
		Initialize AIDE:\n
		# aide --init\n
		Notes:\n
		The prelinking feature can interfere with AIDE because it alters binaries to speed up their start up times. Run prelink -ua to restore the binaries to their prelinked state, thus avoiding false positives from AIDE.\n"
	fi
}

ensure_filesystem_integrity_is_regularly_checked () {
        echo -e "\e[92m== 1.3.2 Ensure filesystem integrity is regularly checked ==\e\n"
	if [[ "$(grep -r aide /etc/cron.* /etc/crontab 2> /dev/null)" = "" ]]
		then echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands to determine if there is a cron job scheduled to run the aide check.\n
		# crontab -u root -l | grep aide\n
		# grep -r aide /etc/cron.* /etc/crontab\n
		Ensure a cron job in compliance with site policy is returned.\n
		Remediation:
		Run the following command:\n
		# crontab -u root -e
		Add the following line to the crontab:
		0 5 * * * /usr/bin/aide --check\n"
	else
		echo -e "Passed!\n"
	fi
}

ensure_permissions_on_bootloader () {
	echo -e "\e[92m== 1.4.1 Ensure permissions on bootloader config are configured == \e\n"
	if [[ "$(stat -c %a /boot/grub/grub.cfg)" = "600" && "$(stat -c %U:%G /boot/grub/grub.cfg)" = "root:root" ]]
		then echo -e "Passed!\n"
	else
        echo -e "\e[31mFailed!\e[0m : \n                Audit:
	Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other:\n
	# stat /boot/grub/grub.cfg
	Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n
	Remediation:
	Run the following commands to set permissions on your grub configuration:
	# chown root:root /boot/grub/grub.cfg
	# chmod og-rwx /boot/grub/grub.cfg"
	fi
}

ensure_bootloader_password () {
	echo -e "\e[92m== 1.4.2 Ensure bootloader password is set == \e\n"
	if [[ "$(grep '^set superusers' /boot/grub/grub.cfg 2> /dev/null )" != "" && "$(grep '^password' /boot/grub/grub.cfg 2> /dev/null)" != "" ]]
		then echo -e "Passed!\n"
	else
		echo -e "\e[31mFailed!\e[0m : \n                Audit:
	Run the following commands and verify output matches:
	# grep '^set superusers' /boot/grub/grub.cfg
	set superusers='<username>'
	# grep '^password' /boot/grub/grub.cfg
	password_pbkdf2 <username> <encrypted-password>\n

	Remediation:
	Create an encrypted password with grub-mkpasswd-pbkdf2:
	# grub-mkpasswd-pbkdf2
	Enter password: <password>
	Reenter password: <password>
	Your PBKDF2 is <encrypted-password>\n

	Add the following into /etc/grub.d/00_header or a custom /etc/grub.d configuration file:
	cat <<EOF
	set superusers='<username>'
	password_pbkdf2 <username> <encrypted-password> EOF\n

	Run the following command to update the grub2 configuration:
	# update-grub\n

	Notes:
	This recommendation is designed around the grub bootloader, if LILO or another bootloader is in use in your environment enact equivalent settings.\n"

	fi
}

ensure_auth_required_for_single_user_mode () {
	echo -e "\e[92m== 1.4.3 Ensure authentication required for single user mode ==\e\n"
	if [[ "$(grep ^root:[*\!]: /etc/shadow)" = "" ]]
	then echo -e "Passed!\n"
	else
        echo -e "\e[31mFailed!\e[0m : \n                Audit:
	Perform the following to determine if a password is set for the root user:
	# grep ^root:[*\!]: /etc/shadow
	No results should be returned.

	Remediation:
	Run the following command and follow the prompts to set a password for the root user:
	# passwd root\n"

	fi
}

ensure_core_dumps_are_restricted () {
        echo -e "\e[92m== 1.5.1 Ensure core dumps are restricted ==\e\n"
	if [[ "$(grep 'hard core' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null | cut -d \: -f2)" = "* hard core 0" && "$(sysctl fs.suid_dumpable 2>/dev/null)" = "fs.suid_dumpable = 0" ]]
		then echo -e "Passed!\n"
	else
        echo -e "\e[31mFailed!\e[0m : \n                Audit:
	Run the following commands and verify output matches:
	# grep 'hard core' /etc/security/limits.conf /etc/security/limits.d/*
	* hard core 0\n
	# sysctl fs.suid_dumpable
	fs.suid_dumpable = 0\n

	Remediation:
	Add the following line to the /etc/security/limits.conf file or a /etc/security/limits.d/* file:
	* hard core 0\n
	Set the following parameter in the /etc/sysctl.conf file:
	fs.suid_dumpable = 0\n
	Run the following command to set the active kernel parameter:
	# sysctl -w fs.suid_dumpable=0\n"

	fi
}


ensure_xd_nd_support_is_disabled () {
	        echo -e "\e[92m== 1.5.2 Ensure XD/NX support is enabled (Not Scored) ==\e\n"
		if [[ "$(dmesg | grep NX | grep active)" != "" ]]
			then echo -e "Passed!\n"
		else
		echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify your kernel has identified and activated NX/XD protection.
		# dmesg | grep NX
		NX (Execute Disable) protection: active\n

		Remediation:
		On 32 bit systems install a kernel with PAE support, no installation is required on 64 bit systems:
		If necessary configure your bootloader to load the new kernel and reboot the system. You may need to enable NX or XD support in your bios.\n

		Notes:
		Ensure your system supports the XD or NX bit and has PAE support before implementing this recommendation as this may prevent it from booting if these are not supported by your hardware.\n"

	fi
}


ensure_address_space_layout_randomization () {
                echo -e "\e[92m== 1.5.3 Ensure address space layout randomization (ASLR) is enabled ==\e\n"
		if [[ "$(sysctl kernel.randomize_va_space)" = "kernel.randomize_va_space = 2" ]]
			then echo -e "Passed!\n"
		else
			echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Audit:
		Run the following command and verify output matches:
		# sysctl kernel.randomize_va_space
		kernel.randomize_va_space = 2\n

		Remediation:
		Set the following parameter in the /etc/sysctl.conf file:\n
		kernel.randomize_va_space = 2\n

		Run the following command to set the active kernel parameter:
		# sysctl -w kernel.randomize_va_space=2\n"

		fi
}

ensure_prelink_is_disabled () {
                echo -e "\e[92m== 1.5.4 Ensure prelink is disabled ==\e\n"
		if [[ "$(dpkg -s prelink 2>/dev/null | grep Status)" =~ 'Status: deinstall' || "$(dpkg -s prelink 2>/dev/null)" = "" ]]
		then echo -e "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify prelink is not installed:
		# dpkg -s prelink\n

		Remediation:
		Run the following command to restore binaries to normal:
		# prelink -ua\n

		Run the following command to uninstall prelink:
		# apt-get remove prelink\n"

		fi
}

ensure_selinux_is_not_disabled_in_bootloader () {
                echo -e "\e[92m== 1.6.1.1 Ensure SELinux is not disabled in bootloader configuration ==\e\n"
		if [[ "$(egrep 'selinux=0|enforcing=0' /boot/grub/grub.cfg 2>/dev/null)" = "" ]]
		then echo -e "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that no linux line has the selinux=0 or enforcing=0 parameters set:
		# grep "^\s*linux" /boot/grub/grub.cfg\n

		Remediation:
		Edit /etc/default/grub and remove all instances of selinux=0 and enforcing=0 from all CMDLINE_LINUX parameters:
		GRUB_CMDLINE_LINUX_DEFAULT='quiet'
		GRUB_CMDLINE_LINUX=''\n

		Run the following command to update the grub2 configuration:
		# update-grub\n

		Notes:
		This recommendation is designed around the grub bootloader, if LILO or another bootloader is in use in your environment enact equivalent settings.\n"

		fi
}

ensure_selinux_state_is_enforcing () {
                echo -e "\e[92m== 1.6.1.2 Ensure the SELinux state is enforcing ==\e\n"
		if [[ "$(grep SELINUX=enforcing /etc/selinux/config 2>/dev/null)" = "SELINUX=enforcing" && "$(sestatus 2>/dev/null | grep status)" = "SELinux status: enabled"  ]]
		then echo "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and ensure output matches:
		# grep SELINUX=enforcing /etc/selinux/config
		SELINUX=enforcing
		# sestatus
		SELinux status: enabled
		Current mode: enforcing
		Mode from config file: enforcing\n

		Remediation:
		Edit the /etc/selinux/config file to set the SELINUX parameter:
		SELINUX=enforcing\n"

		fi
}

ensure_selinux_policy_is_configured () {
                echo -e "\e[92m== 1.6.1.3 Ensure SELinux policy is configured ==\e\n"
		if [[ "$(grep SELINUXTYPE= /etc/selinux/config 2>/dev/null)" = "SELINUXTYPE=ubuntu" || "$(grep SELINUXTYPE= /etc/selinux/config 2>/dev/null)" = "SELINUXTYPE=default" || "$(grep SELINUXTYPE= /etc/selinux/config 2>/dev/null)" = "SELINUXTYPE=mls" && "$(sestatus 2>/dev/null)" && "$(sestatus)" =~ "Policy from config file: (ubuntu|default|mls)" ]]
		then echo -e "Passed!\n"
                else
		echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and ensure output matches "ubuntu", "default" or "mls":
		# grep SELINUXTYPE= /etc/selinux/config
		SELINUXTYPE=ubuntu
		# sestatus
		Policy from config file: ubuntu\n


		Remediation:
		Edit the /etc/selinux/config file to set the SELINUXTYPE parameter:
		SELINUXTYPE=ubuntu\n

		Notes:
		If your organization requires stricter policies, ensure that they are set in the/etc/selinux/config file.\n"

		fi
}

ensure_no_unconfined_daemons_exist () {
                echo -e "\e[92m== 1.6.1.4 Ensure no unconfined daemons exist ==\e\n"
		if [[ $(ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }') = "" ]]
		then echo -e "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify not output is produced:
		ps -eZ | egrep \"initrc\" | egrep -vw \"tr|ps|egrep|bash|awk\" | tr ':' ' ' | awk '{ print $NF }'\n

		Remediation:
		Investigate any unconfined daemons found during the audit action. They may need to have an existing security context assigned to them or a policy built for them.\n

		Notes:
		Occasionally certain daemons such as backup or centralized management software may require running unconfined. Any such software should be carefully analyzed and documented before such an exception is made.\n"

		fi
}

ensure_apparmor_is_not_disabled_in_bootloader () {
                echo -e "\e[92m== 1.6.2.1 Ensure AppArmor is not disabled in bootloader configuration ==\e\n"
		if [[ "$(grep apparmor=0 /boot/grub/grub.cfg 2>/dev/null)" = "" ]]
		then echo -e "Passed!\n"
		else
		echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that no linux line the apparmor=0 parameter set:
		# grep "^\s*linux" /boot/grub/grub.cfg\n

		Remediation:
		Edit /etc/default/grub and remove all instances of apparmor=0 from all CMDLINE_LINUX parameters:
		GRUB_CMDLINE_LINUX_DEFAULT="quiet"
		GRUB_CMDLINE_LINUX=""\n

		Run the following command to update the grub2 configuration:
		# update-grub

		Notes:
		This recommendation is designed around the grub bootloader, if LILO or another bootloader is in use in your environment enact equivalent settings.\n"

		fi
}

ensure_all_apparmor_profiles_are_enforcing () {
                echo -e "\e[92m== 1.6.2.2 Ensure all AppArmor Profiles are enforcing ==\e\n"
		echo -e "\e[31m Verify that profiles are loaded, no profiles are in complain mode, and no processes are unconfined from the output below:\033[0m\n"
		echo -e "\n==\n"
if [[ "$(apparmor_status 2>/dev/null)" = "" ]]
then echo "No output was found"
else
apparmor_status 2>/dev/null
fi
		echo -e "\n==\n"
		echo -e "\n		Remediation:
		Run the following command to set all profiles to enforce mode:
		# aa-enforce /etc/apparmor.d/*\n

		Any unconfined processes may need to have a profile created or activated for them and then be restarted.\n"

}

ensure_selinux_or_apparmor_are_installed () {
                echo -e "\e[92m== 1.6.3 Ensure SELinux or AppArmor are installed (Not Scored) ==\n"
		if [[ "$(dpkg -s selinux 2>/dev/null | grep Status )" =~ Status:.install.ok* || "$(dpkg -s apparmor 2>/dev/null | grep Status)" =~ Status:.install.ok* ]]
		then echo -e "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify either SELinux or AppArmor is installed:
		# dpkg -s selinux
		# dpkg -s apparmor\n

		Remediation:
		Run one of the following commands to install SELinux or apparmor:
		# apt-get install selinux
		# apt-get install apparmor\n"

		fi
}

ensure_message_of_the_day_is_configured () {
                echo -e "\e[92m== 1.7.1.1 Ensure message of the day is configured properly ==\n"
		echo -e "\e[31mVerify that the following output from /etc/motd matches site policy:\n\n==\n"
		if [[ "$(cat /etc/motd 2> /dev/null)" = "" ]]
		then echo -e "/etc/motd file is empty\n\n==\n"
		else
cat /etc/motd 2>/dev/null
		echo -e "\n==\n\n"

		fi
		if [[ "$(egrep '(\\v|\\r|\\m|\\s)' /etc/motd 2>/dev/null)" = "" ]]
		then echo -e "\e[92mPassed!\033[0m\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that the contents match site policy:
		# cat /etc/motd\n

		Run the following command and verify no results are returned:
		# egrep '(\\v|\\r|\\m|\\s)' /etc/motd\n

		Remediation:
		Edit the /etc/motd file with the appropriate contents according to your site policy, remove any instances of \m, \r, \s, or \v."

		fi

}

ensure_local_login_warning_banner_is_configured_properly () {
                echo -e "\e[92m== 1.7.1.2 Ensure local login warning banner is configured properly (Not Scored) ==\n"
                echo -e "\e[31mVerify that the following output from /etc/issue matches site policy:\n\n==\n"
                if [[ "$(cat /etc/issue 2> /dev/null)" = "" ]]
                then echo -e "/etc/issue file is empty\n\n==\n"
                else
cat /etc/issue 2>/dev/null
                echo -e "\n==\n\n"

                fi
                if [[ "$(egrep '(\\v|\\r|\\m|\\s)' /etc/issue 2>/dev/null)" = "" ]]
                then echo -e "\e[92mPassed!\033[0m\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify that the contents match site policy:
                # cat /etc/issue\n

                Run the following command and verify no results are returned:
                # egrep '(\\v|\\r|\\m|\\s)' /etc/issue\n

                Remediation:
                Edit the /etc/issue file with the appropriate contents according to your site policy, remove any instances of \m, \r, \s, or \v:
		# echo \"Authorized uses only. All activity may be monitored and reported.\" \> /etc/issue"

                fi

}

ensure_remote_login_warning_banner_is_configured () {
                echo -e "\e[92m== 1.7.1.3 Ensure remote login warning banner is configured properly (Not Scored) ==\n"
                echo -e "\e[31mVerify that the following output from /etc/issue.net matches site policy:\n\n==\n"
                if [[ "$(cat /etc/issue.net 2> /dev/null)" = "" ]]
                then echo -e "/etc/issue.net file is empty\n\n==\n"
                else
cat /etc/issue.net 2>/dev/null
                echo -e "\n==\n\n"

                fi
                if [[ "$(egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net 2>/dev/null)" = "" ]]
                then echo -e "\e[92mPassed!\033[0m\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify that the contents match site policy:
                # cat /etc/issue.net\n

                Run the following command and verify no results are returned:
                # egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net\n

                Remediation:
                Edit the /etc/issue.net file with the appropriate contents according to your site policy, remove any instances of \m, \r, \s, or \v:
                # echo \"Authorized uses only. All activity may be monitored and reported.\" \> /etc/issue.net"

                fi

}

ensure_permissions_on_etc_motd_are_configured () {
                echo -e "\e[92m== 1.7.1.4 Ensure permissions on /etc/motd are configured (Not Scored) ==\n"
	        if [[ "$(stat -c %a /etc/motd 2>/dev/null)" = "644" && "$(stat -c %U:%G /etc/motd 2>/dev/null)" = "root:root" ]]
		then echo -e "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify Uid and Gid are both 0/root and Access is 644:
		# stat /etc/motd
		Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)\n

		Remediation:
		Run the following commands to set permissions on /etc/motd:
		# chown root:root /etc/motd
		# chmod 644 /etc/motd\n"

		fi
}


ensure_permissions_on_etc_issue_are_configured () {
                echo -e "\e[92m== 1.7.1.5 Ensure permissions on /etc/issue are configured (Not Scored) ==\n"
                if [[ "$(stat -c %a /etc/issue 2>/dev/null)" = "644" && "$(stat -c %U:%G /etc/issue 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify Uid and Gid are both 0/root and Access is 644:
                # stat /etc/issue
                Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)\n

                Remediation:
                Run the following commands to set permissions on /etc/issue:
                # chown root:root /etc/issue
                # chmod 644 /etc/issue\n"

                fi
}

ensure_permissions_on_etc_issue_net_are_configured () {
                echo -e "\e[92m== 1.7.1.6 Ensure permissions on /etc/issue.net are configured (Not Scored) ==\n"
                if [[ "$(stat -c %a /etc/issue.net 2>/dev/null)" = "644" && "$(stat -c %U:%G /etc/issue.net 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify Uid and Gid are both 0/root and Access is 644:
                # stat /etc/issue.net
                Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)\n

                Remediation:
                Run the following commands to set permissions on /etc/issue.net:
                # chown root:root /etc/issue.net
                # chmod 644 /etc/issue.net\n"

                fi
}

ensure_gdm_login_banner_is_configured () {
                echo -e "\e[92m== 1.7.2 Ensure GDM login banner is configured ==\n"
		if [[ "$(apt list --installed 2> /dev/null | grep -i ^gdm)" = "" ]]
		then echo -e "Passed!\n"
		else
# To-do: Make the checks for these contents automated
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		If GDM is installed on the system verify that /etc/dconf/profile/gdm exists and contains the following:
		user-db:user
		system-db:gdm
		file-db:/usr/share/gdm/greeter-dconf-defaults\n

		Then verify the banner-message-enable and banner-message-text options are configured in /etc/dconf/db/gdm.d/01-banner-message:
		[org/gnome/login-screen]
		banner-message-enable=true
		banner-message-text='<banner message>'\n

		Remediation:
		Create the /etc/dconf/profile/gdm file with the following contents:
		user-db:user
		system-db:gdm
		file-db:/usr/share/gdm/greeter-dconf-defaults\n

		Create or edit the banner-message-enable and banner-message-text options in /etc/dconf/db/gdm.d/01-banner-message:
		[org/gnome/login-screen]
		banner-message-enable=true
		banner-message-text='Authorized uses only. All activity may be monitored and
		reported.'\n

		Run the following command to update the system databases:
		# dconf update\n

		Notes:
		Additional options and sections may appear in the /etc/dconf/db/gdm.d/01-banner- message file.
		If a different GUI login service is in use, consult your documentation and apply an equivalent banner.\n"

		fi
}

ensure_updates_patches_and_additional_security () {
                echo -e "\e[92m== 1.8 Ensure updates, patches, and additional security software are installed (Not Scored) ==\n"
		if [[ "$(apt-get update 1> /dev/null && apt-get upgrade -s 2>/dev/null | grep 'The following packages will be upgraded')" = "" ]]
		then echo -e "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify there are no updates or patches to install:
		# apt-get -s upgrade\n

		Remediation:
		Use your package manager to update all packages on the system according to site policy.

		Notes:
		Site policy may mandate a testing period before install onto production systems for available updates.\n"

		fi

}

ensure_chargen_services_are_not_enabled () {
                echo -e "\e[92m== 2.1.1 Ensure chargen services are not enabled ==\e\n"
		if [[ "$(grep -R "^chargen" /etc/inetd.* 2> /dev/null)" = "" ]]
                then echo -e "Passed!\n"
		else
		echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Verify the chargen service is not enabled. Run the following command and verify results are as indicated:
		grep -R "^chargen" /etc/inetd.*\n

		No results should be returned\n

		check /etc/xinetd.conf and /etc/xinetd.d/* and verify all chargen services have
		disable = yes set.i\n

		Remediation:
		Comment out or remove any lines starting with chargen from /etc/inetd.conf and /etc/inetd.d/*.
		Set disable = yes on all chargen services in /etc/xinetd.conf and /etc/xinetd.d/*.\n"

		fi

}

ensure_daytime_services_are_not_enabled () {
                echo -e "\e[92m== 2.1.2 Ensure daytime services are not enabled ==\n"
		if [[ "$(grep -R "^daytime" /etc/inetd.* 2>/dev/null)" = "" ]]
		then echo -e "Passed!\n"
		else
		echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Verify the daytime service is not enabled. Run the following command and verify results are as indicated:
		grep -R "^daytime" /etc/inetd.*\n

		No results should be returned

		Check /etc/xinetd.conf and /etc/xinetd.d/* and verify all daytime services have disable = yes set.

		Remediation:
		Comment out or remove any lines starting with daytime from /etc/inetd.conf and /etc/inetd.d/*.
		Set disable = yes on all daytime services in /etc/xinetd.conf and /etc/xinetd.d/*.\n"

		fi

}

ensure_discard_services_are_not_enabled () {
                echo -e "\e[92m== 2.1.3 Ensure discard services are not enabled ==\n"
		if [[ "$(grep -R "^discard" /etc/inetd.* 2>/dev/null)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Verify the discard service is not enabled. Run the following command and verify results are as indicated:
		grep -R \"^discard\" /etc/inetd.*\n

		No results should be returned.  Check /etc/xinetd.conf and /etc/xinetd.d/* and verify all discard services have disable = yes set.\n

		Remediation:
		Comment out or remove any lines starting
		with discard from /etc/inetd.conf and /etc/inetd.d/*.
		Set disable = yes on all discard services in /etc/xinetd.conf and /etc/xinetd.d/*.\n"

		fi
}

ensure_echo_services_are_not_enabled () {
                echo -e "\e[92m== 2.1.4 Ensure echo services are not enabled ==\n"
		if [[ "$(grep -R "^echo" /etc/inetd.* 2> /dev/null)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Verify the echo service is not enabled. Run the following command and verify results are as indicated:
		grep -R "^echo" /etc/inetd.*\n

		No results should be returned.  Check /etc/xinetd.conf and /etc/xinetd.d/* and verify all echo services have disable = yes set.\n

		Remediation:
		Comment out or remove any lines starting with echo from /etc/inetd.conf and /etc/inetd.d/*.  Set disable = yes on all echo services in /etc/xinetd.conf and /etc/xinetd.d/*.\n"

		fi

}

ensure_time_services_are_not_enabled () {
                echo -e "\e[92m== 2.1.5 Ensure time services are not enabled ==\n"
		if [[ "$(grep -R "^time" /etc/inetd.* 2>/dev/null)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Verify the time service is not enabled. Run the following command and verify results are as indicated:
		grep -R "^time" /etc/inetd.*\n

		No results should be returned.  Check /etc/xinetd.conf and /etc/xinetd.d/* and verify all time services have disable = yes set.\n

		Remediation:
		Comment out or remove any lines starting with time from /etc/inetd.conf and /etc/inetd.d/*.  Set disable = yes on all time services in /etc/xinetd.conf and /etc/xinetd.d/*.\n"

		fi
}

ensure_rsh_server_is_not_enabled () {
                echo -e "\e[92m== 2.1.6 Ensure rsh server is not enabled ==\n"
		if [[ "$(grep -R "^shell" /etc/inetd.* 2>/dev/null)" = "" && "$(grep -R "^login" /etc/inetd.* 2>/dev/null)" = "" && "$(grep -R "^exec" /etc/inetd.* 2>/dev/null)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Verify the rsh services are not enabled. Run the following commands and verify results are as indicated:
		grep -R \"^shell\" /etc/inetd.*
		grep -R \"^login\" /etc/inetd.*
		grep -R \"^exec\" /etc/inetd.*\n

		No results should be returned.  Check /etc/xinetd.conf and /etc/xinetd.d/* and verify all rsh, rlogin, and rexec services have disable = yes set.\n

		Remediation:
		Comment out or remove any lines starting with shell, login, or exec from /etc/inetd.conf and /etc/inetd.d/*.
		Set disable = yes on all rsh, rlogin,
		and rexec services in /etc/xinetd.conf and /etc/xinetd.d/*.\n"

		fi
}


ensure_talk_server_is_not_enabled () {
                echo -e "\e[92m== 2.1.7 Ensure talk server is not enabled ==\n"
                if [[ "$(grep -R "^talk" /etc/inetd.* 2>/dev/null)" = "" && "$(grep -R "^ntalk" /etc/inetd.* 2> /dev/null)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Verify the talk service is not enabled. Run the following commands and verify results are as indicated:
		grep -R "^talk" /etc/inetd.*
		grep -R "^ntalk" /etc/inetd.*\n

		No results should be returned.  Check /etc/xinetd.conf and /etc/xinetd.d/* and verify all talk services have disable = yes set.

		Remediation:
		Comment out or remove any lines starting with talk or ntalk from /etc/inetd.conf and /etc/inetd.d/*.
		Set disable = yes on all talk services in /etc/xinetd.conf and /etc/xinetd.d/*.\n"

		fi
}


ensure_telnet_server_is_not_enabled () {
                echo -e "\e[92m== 2.1.8 Ensure telnet server is not enabled ==\n"
		if [[ "$(grep -R "^telnet" /etc/inetd.* 2>/dev/null)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Verify the telnet service is not enabled. Run the following command and verify results are as indicated:
		grep -R \"^telnet\" /etc/inetd.*\n

		No results should be returned.  Check /etc/xinetd.conf and /etc/xinetd.d/* and verify all telnet services have disable = yes set.\n

		Remediation:
		Comment out or remove any lines starting
		with telnet from /etc/inetd.conf and /etc/inetd.d/*.
		Set disable = yes on all telnet services in /etc/xinetd.conf and /etc/xinetd.d/*.\n"

		fi
}

ensure_tftpt_server_is_not_enabled () {
                echo -e "\e[92m== 2.1.9 Ensure tftp server is not enabled ==\n"
		if [[ "$(grep -R "^tftp" /etc/inetd.* 2> /dev/null)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Verify the tftp service is not enabled. Run the following command and verify results are as indicated:
		grep -R "^tftp" /etc/inetd.*\n

		No results should be returned.  Check /etc/xinetd.conf and /etc/xinetd.d/* and verify all tftp services have disable = yes set.\n

		Remediation:
		Comment out or remove any lines starting with tftp from /etc/inetd.conf and /etc/inetd.d/*.  Set disable = yes on all tftp services in /etc/xinetd.conf and /etc/xinetd.d/*.\n"

		fi
}

ensure_xinetd_is_not_enabled () {
                echo -e "\e[92m== 2.1.10 Ensure xinetd is not enabled ==\n"
		if [[ "$(systemctl is-enabled xinetd 2>/dev/null)" = "disabled" || "$(systemctl is-enabled xinetd 2>/dev/null)" = "" ]]
		then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify xinetd is not enabled:
		   # systemctl is-enabled xinetd
		   disabled\n

		Verify result is not "enabled".\n

		Remediation:
		Run the following command to disable xinetd:
		# systemctl disable xinetd\n

		Notes:
		Additional methods of disabling a service exist. Consult your distribution documentation for appropriate methods.\n"

		fi
}


ensure_time_synchronization_is_in_use () {
                echo -e "\e[92m== 2.2.1.1 Ensure time synchronization is in use (Not Scored) ==\n"
		if [[ "$(dpkg -s ntp 2> /dev/null | grep Status)" = "Status: install ok installed" || "$(dpkg -s chrony 2>/dev/null | grep Status)" = "Status: install ok installed" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:

		On physical systems or virtual systems where host based time synchronization is not available run the following commands and verify either NTP or chrony is installed:
		# dpkg -s ntp
		# dpkg -s chrony\n

		On virtual systems where host based time synchronization is available consult your virtualization software documentation and verify that host based synchronization is in use.\n

		Remediation:
		On physical systems or virtual systems where host based time synchronization is not available install NTP or chrony using one of the following commands:
		# apt-get install ntp
		# apt-get install chrony\n

		On virtual systems where host based time synchronization is available consult your virtualization software documentation and setup host based synchronization.\n"

		fi
}

ensure_ntp_is_configured () {
                echo -e "\e[92m== 2.2.1.2 Ensure ntp is configured ==\n"
                if [[ "$(dpkg -s ntp 2> /dev/null | grep Status)" != "Status: install ok installed" ]]
		then echo -e "NTP is not installed.  No action necessary\n"
		elif [[ "$(dpkg -s ntp 2> /dev/null | grep Status)" = "Status: install ok installed" && "$(grep '^restrict' /etc/ntp.conf 2>/dev/null | grep 4)" = "" || "$(grep '^restrict' /etc/ntp.conf 2>/dev/null | grep 6)" = "" || "$(grep '^server' /etc/ntp.conf 2>/dev/null)" = "" || "$(grep "RUNASUSER=ntp" /etc/init.d/ntp 2>/dev/null)" = "" ]]
		then echo -e "\e[31mNTP is installed but not configured.\n
		Audit:
		Run the following command and verify output matches:
		# grep "^restrict" /etc/ntp.conf
		restrict -4 default kod nomodify notrap nopeer noquery
		restrict -6 default kod nomodify notrap nopeer noquery\n

		The -4 in the first line is optional and options after default can appear in any order. Additional restriction lines may exist.
		Run the following command and verify remote server is configured properly:
		#  grep '^server' /etc/ntp.conf
		server <remote-server>\n

		Multiple servers may be configured.
		Verify that ntp is configured to run as the ntp user by running the following command:
		# grep "RUNASUSER=ntp" /etc/init.d/ntp
		RUNASUSER=ntp\n

		Remediation:
		Add or edit restrict lines in /etc/ntp.conf to match the following:
		restrict -4 default kod nomodify notrap nopeer noquery
		restrict -6 default kod nomodify notrap nopeer noquery\n

		Add or edit server lines to /etc/ntp.conf as appropriate:
		server <remote-server>\n

		Configure ntp to run as the ntp user by adding or editing the following file:
		/etc/init.d/ntp:
		RUNASUSER=ntp\n"

		else echo -e "Passed!\n"

		fi
}

ensure_chrony_is_configured () {
                echo -e "\e[92m== 2.2.1.3 Ensure chrony is configured ==\n"
		if [[ "$(dpkg -s chrony 2> /dev/null | grep Status)" != "Status: install ok installed" ]]
                then echo -e "Chrony is not installed.  No action necessary\n"
		elif [[ "$(dpkg -s chrony 2> /dev/null | grep Status)" = "Status: install ok installed" && "$(grep '^server' /etc/chrony/chrony.conf 2>/dev/null)" = "" || "$(ps -ef 2> /dev/null | grep chronyd | awk '{print $1}')" != "_chrony" ]]
		then echo -e "\e[31mChrony is installed but not configured.\n
		Audit:
		Run the following command and verify remote server is configured properly:
		# grep "^server" /etc/chrony/chrony.conf
		server <remote-server>\n

		Multiple servers may be configured.
		Run the following command and verify the first field for the chronyd process is _chrony:
		# ps -ef | grep chronyd
		_chrony     491     1  0 20:32 ?        00:00:00 /usr/sbin/chronyd\n

		Remediation:
		Add or edit server lines to /etc/chrony/chrony.conf as appropriate:
		server <remote-server>\n

		Configure chrony to run as the chrony user by configuring the appropriate startup script for your distribution. Startup scripts are typically stored in /etc/init.d or /etc/systemd.\n"

		else echo -e "Passed!\n"

		fi
}

ensure_x_window_system_is_not_installed () {
                echo -e "\e[92m== 2.2.2 Ensure X Window System is not installed ==\n"
		if [[ "$(dpkg -l xserver-xorg* 2>/dev/null | grep ii)" = "" ]]
		then echo -e "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify X Windows System is not installed:
		dpkg -l xserver-xorg*\n

		Remediation:
		Run the following command to remove the X Windows System packages:
		apt-get remove xserver-xorg*\n"

		fi
}

ensure_avahi_server_is_not_installed () {
                echo -e "\e[92m== 2.2.3 Ensure Avahi Server is not enabled ==\n"
		if [[ "$(systemctl is-enabled avahi-daemon 2>/dev/null)" = "" || "$(systemctl is-enabled avahi-daemon 2>/dev/null)" = "disabled" || "$(systemctl is-enabled avahi-daemon 2>/dev/null)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify avahi-daemon is not enabled:
		# systemctl is-enabled avahi-daemon
		disabled \n

		Verify result is not \"enabled\".\n

		Remediation:
		Run the following command to disable avahi-daemon:
		# systemctl disable avahi-daemon\n"

		fi
}

ensure_cups_is_not_enabled () {
                echo -e "\e[92m== 2.2.4 Ensure CUPS is not enabled ==\n"
                if [[ "$(systemctl is-enabled cups 2>/dev/null)" = "" || "$(systemctl is-enabled cups 2>/dev/null)" = "disabled" || "$(systemctl is-enabled cups 2>/dev/null)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify cups is not enabled:
		# systemctl is-enabled cups
		disabled\n

		Verify result is not "enabled".\n

		Remediation:
		Run the following command to disable cups:
		# systemctl disable cups\n

		Impact:
		Disabling CUPS will prevent printing from the system, a common task for workstation systems.\n"

		fi


}

ensure_dhcp_server_is_not_enabled () {
                echo -e "\e[92m== 2.2.5 Ensure DHCP Server is not enabled ==\n"
                if [[ "$(systemctl is-enabled isc-dhcp-server 2>/dev/null)" = "" || "$(systemctl is-enabled isc-dhcp-server)" = "disabled" || "$(systemctl is-enabled isc-dhcp-server)" = "masked" && "$(systemctl is-enabled isc-dhcp-server6 2>/dev/null)" = "" || "$(systemctl is-enabled isc-dhcp-server6)" = "disabled" || "$(systemctl is-enabled isc-dhcp-server6)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands to verify dhcpd is not enabled:
		# systemctl is-enabled isc-dhcp-server
		disabled
		# systemctl is-enabled isc-dhcp-server6
		disabled\n

		Verify both results are not \"enabled\".\n

		Remediation:
		Run the following commands to disable dhcpd:
		# systemctl disable isc-dhcp-server
		# systemctl disable isc-dhcp-server6\n"

		fi
}

ensure_ldap_server_is_not_enabled () {
                echo -e "\e[92m== 2.2.6 Ensure LDAP Server is not enabled ==\n"
                if [[ "$(systemctl is-enabled slapd 2>/dev/null)" = "" || "$(systemctl is-enabled slapd)" = "disabled" || "$(systemctl is-enabled slapd)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify slapd is not enabled:
		# systemctl is-enabled slapd
		disabled\n

		Verify result is not \"enabled\".

		Remediation:
		Run the following command to disable slapd:
		# systemctl disable slapd\n"

		fi
}

ensure_nfs_and_rpc_are_not_enabled () {
                echo -e "\e[92m== 2.2.7 Ensure NFS and RPC are not enabled ==\n"
                if [[ "$(systemctl is-enabled nfs-kernel-server 2>/dev/null)" = "" || "$(systemctl is-enabled nfs-kernel-server)" = "disabled" || "$(systemctl is-enabled nfs-kernel-server)" = "masked" && "$(systemctl is-enabled rpcbind 2>/dev/null)" = "" || "$(systemctl is-enabled rpcbind)" = "disabled" || "$(systemctl is-enabled rpcbind)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify nfs is not enabled:
		# systemctl is-enabled nfs-kernel-server\n

		Verify result is not \"enabled\".

		Run the following command to verify rpcbind is not enabled:
		# systemctl is-enabled rpcbind
		disabled\n

		Verify result is not \"enabled\".

		Remediation:
		Run the following commands to disable nfs and rpcbind:
		# systemctl disable nfs-kernel-server
		# systemctl disable rpcbind\n"

		fi
}

ensure_dns_server_is_not_enabled () {
                echo -e "\e[92m== 2.2.8 Ensure DNS Server is not enabled ==\n"
                if [[ "$(systemctl is-enabled bind9 2>/dev/null)" = "" || "$(systemctl is-enabled bind9)" = "disabled" || "$(systemctl is-enabled bind9)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify named is not enabled:
		# systemctl is-enabled bind9
		disabled\n

		Verify result is not \"enabled\".\n

		Remediation:
		Run the following command to disable named:
		# systemctl disable bind9\n"

		fi
}

ensure_ftp_server_is_not_enabled () {
                echo -e "\e[92m== 2.2.9 Ensure FTP Server is not enabled ==\n"
                if [[ "$(systemctl is-enabled vsftpd 2>/dev/null)" = "" || "$(systemctl is-enabled vsftpd)" = "disabled" || "$(systemctl is-enabled vsftpd)" = "masked" ]]
                then echo -e "Passed!\n
		Notes:
		Check is for vsftpd.  Additional FTP servers also exist and should be audited.\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command to verify vsftpd is not enabled:
                # systemctl is-enabled vsftpd
                disabled\n

                Verify result is not \"enabled\".\n

                Remediation:
                Run the following command to disable vsftpd:
                # systemctl disable vsftpd\n

		Notes:
		Additional FTP servers also exist and should be audited.\n"

                fi
}


ensure_http_server_is_not_enabled () {
                echo -e "\e[92m== 2.2.10 Ensure HTTP Server is not enabled ==\n"
                if [[ "$(systemctl is-enabled apache2 2>/dev/null)" = "" || "$(systemctl is-enabled apache2 2> /dev/null)" = "disabled" || "$(systemctl is-enabled apache2 2> /dev/null)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command to verify apache2 is not enabled:
                # systemctl is-enabled apache2
                disabled\n

                Verify result is not \"enabled\".\n

                Remediation:
                Run the following command to disable apache2:
                # systemctl disable apache2\n"

                fi
}

ensure_imap_and_pop3_server_is_not_enabled () {
                echo -e "\e[92m== 2.2.11 Ensure IMAP and POP3 Server is not enabled ==\n"
                if [[ "$(systemctl is-enabled dovecot 2>/dev/null)" = "" || "$(systemctl is-enabled dovecot)" = "disabled" || "$(systemctl is-enabled dovecot)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command to verify dovecot is not enabled:
                # systemctl is-enabled dovecot
                disabled\n

                Verify result is not \"enabled\".\n

                Remediation:
                Run the following command to disable dovecot:
                # systemctl disable dovecot\n

		Notes:
		Several IMAP/POP3 servers exist and can use other service names. exim and cyrus- imap are example services that provide an IMAP server. These and other services should also be audited.\n"

                fi

}

ensure_samba_is_not_enabled () {
                echo -e "\e[92m== 2.2.12 Ensure Samba is not enabled ==\n"
                if [[ "$(systemctl is-enabled smbd 2>/dev/null)" = "" || "$(systemctl is-enabled smbd 2> /dev/null)" = "disabled" || "$(systemctl is-enabled smbd 2> /dev/null)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command to verify smbd is not enabled:
                # systemctl is-enabled smbd
                disabled\n

                Verify result is not \"enabled\".\n

                Remediation:
                Run the following command to disable smbd:
                # systemctl disable smbd\n"

                fi

}

ensure_http_proxy_server_is_not_enabled () {
                echo -e "\e[92m== 2.2.13 Ensure HTTP Proxy Server is not enabled ==\n"
                if [[ "$(systemctl is-enabled squid 2>/dev/null)" = "" || "$(systemctl is-enabled squid 2> /dev/null)" = "disabled" || "$(systemctl is-enabled squid 2> /dev/null)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command to verify squid is not enabled:
                # systemctl is-enabled squid
                disabled\n

                Verify result is not \"enabled\".\n

                Remediation:
                Run the following command to disable squid:
                # systemctl disable squid\n"

                fi

}

ensure_snmp_server_is_not_enabled () {
                echo -e "\e[92m== 2.2.14 Ensure SNMP Server is not enabled ==\n"
                if [[ "$(systemctl is-enabled snmpd 2>/dev/null)" = "" || "$(systemctl is-enabled snmpd 2> /dev/null)" = "disabled" || "$(systemctl is-enabled snmpd 2> /dev/null)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command to verify snmpd is not enabled:
                # systemctl is-enabled snmpd
                disabled\n

                Verify result is not \"enabled\".\n

                Remediation:
                Run the following command to disable snmpd:
                # systemctl disable snmpd\n"

                fi

}

ensure_mail_transfer_agent_is_configured_for_local_only () {
                echo -e "\e[92m== 2.2.15 Ensure mail transfer agent is configured for local-only mode ==\n"
		if [[ "$(netstat -an | grep LIST | grep ":25[[:space:]]" | grep -v 127.0.0.1)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that the MTA is not listening on any non-loopback address (127.0.0.1 or ::1):
		# netstat -an | grep LIST | grep \":25[[:space:]]\"
		tcp 0 0 127.0.0.1:25 0.0.0.0:* LISTEN\n

		Remediation:
		Edit /etc/postfix/main.cf and add the following line to the RECEIVING MAIL section. If the line already exists, change it to look like the line below:
		inet_interfaces = localhost\n

		Restart postfix:
		# service postfix restart\n

		Notes:
		This recommendation is designed around the postfix mail server, depending on your environment you may have an alternative MTA installed such as sendmail. If this is the case consult the documentation for your installed MTA to configure the recommended state.\n"

		fi
}

ensure_rsync_service_is_not_enabled () {
                echo -e "\e[92m== 2.2.16 Ensure rsync service is not enabled ==\n"
                if [[ "$(systemctl is-enabled rsync 2>/dev/null)" = "" || "$(systemctl is-enabled rsync 2> /dev/null)" = "disabled" || "$(systemctl is-enabled rsync 2> /dev/null)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command to verify rsync is not enabled:
                # systemctl is-enabled rsync
                disabled\n

                Verify result is not \"enabled\".\n

                Remediation:
                Run the following command to disable rsync:
                # systemctl disable rsync\n"

                fi

}

ensure_nis_server_is_not_enabled () {
                echo -e "\e[92m== 2.2.17 Ensure NIS server is not enabled ==\n"
                if [[ "$(systemctl is-enabled nis 2>/dev/null)" = "" || "$(systemctl is-enabled nis 2> /dev/null)" = "disabled" || "$(systemctl is-enabled nis 2> /dev/null)" = "masked" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command to verify nis is not enabled:
                # systemctl is-enabled nis
                disabled\n

                Verify result is not \"enabled\".\n

                Remediation:
                Run the following command to disable nis:
                # systemctl disable rsync\n"

                fi

}

ensure_nis_client_is_not_installed () {
                echo -e "\e[92m== 2.3.1 Ensure NIS Client is not installed ==\n"
		if [[ "$(dpkg -s nis 2>/dev/null | grep Status)" = "" || "$(dpkg -s nis 2>/dev/null | grep Status)" =~ ^Status:.deinstall ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify nis is not installed:
		dpkg -s nis\n

		Remediation:
		Run the following command to uninstall nis:
		apt-get remove nis\n

		Impact:
		Many insecure service clients are used as troubleshooting tools and in testing environments. Uninstalling them can inhibit capability to test and troubleshoot. If they are required it is advisable to remove the clients after use to prevent accidental or intentional misuse.\n"

		fi

}

ensure_rsh_client_is_not_installed () {
                echo -e "\e[92m== 2.3.2 Ensure rsh client is not installed ==\n"
                if [[ "$(dpkg -s rsh-client 2>/dev/null | grep Status)" = "" || "$(dpkg -s rsh-client 2>/dev/null | grep Status)" =~ ^Status:.deinstall && "$(dpkg -s rsh-redone-client 2>/dev/null | grep Status)" = "" || "$(dpkg -s rsh-redone-client 2>/dev/null | grep Status)" =~ ^Status:.deinstall ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following commands and verify rsh is not installed:
                dpkg -s rsh-client
		dpkg -s rsh-redone-client\n

                Remediation:
                Run the following command to uninstall rsh:
                apt-get remove rsh-client rsh-redone-client\n

                Impact:
                Many insecure service clients are used as troubleshooting tools and in testing environments. Uninstalling them can inhibit capability to test and troubleshoot. If they are required it is advisable to remove the clients after use to prevent accidental or intentional misuse.\n"

                fi

}

ensure_talk_client_is_not_installed () {
                echo -e "\e[92m== 2.3.3 Ensure talk client is not installed ==\n"
                if [[ "$(dpkg -s talk 2>/dev/null | grep Status)" = "" || "$(dpkg -s talk 2>/dev/null | grep Status)" =~ ^Status:.deinstall ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify talk is not installed:
                dpkg -s talk\n

                Remediation:
                Run the following command to uninstall talk:
                apt-get remove talk\n

                Impact:
                Many insecure service clients are used as troubleshooting tools and in testing environments. Uninstalling them can inhibit capability to test and troubleshoot. If they are required it is advisable to remove the clients after use to prevent accidental or intentional misuse.\n"

                fi

}

ensure_telnet_client_is_not_installed () {
                echo -e "\e[92m== 2.3.4 Ensure telnet client is not installed ==\n"
                if [[ "$(dpkg -s telnet 2>/dev/null | grep Status)" = "" || "$(dpkg -s telnet 2>/dev/null | grep Status)" =~ ^Status:.deinstall* ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify telnet is not installed:
                dpkg -s telnet\n

                Remediation:
                Run the following command to uninstall telnet:
                apt-get remove telnet\n

                Impact:
                Many insecure service clients are used as troubleshooting tools and in testing environments. Uninstalling them can inhibit capability to test and troubleshoot. If they are required it is advisable to remove the clients after use to prevent accidental or intentional misuse.\n"

                fi

}

ensure_ldap_client_is_not_installed () {
                echo -e "\e[92m== 2.3.5 Ensure ldap-utils client is not installed ==\n"
                if [[ "$(dpkg -s ldap-utils 2>/dev/null | grep Status)" = "" || "$(dpkg -s ldap-utils 2>/dev/null | grep Status)" =~ ^Status:.deinstall* ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify ldap-utils is not installed:
                dpkg -s ldap-utils\n

                Remediation:
                Uninstall ldap-utils using the appropriate package manager or manual installation:
                apt-get remove ldap-utils\n

                Impact:
		Removing the LDAP client will prevent or inhibit using LDAP for authentication in your environment.\n"

                fi

}

ensure_ip_forwarding_is_disabled () {
                echo -e "\e[92m== 3.1.1 Ensure IP forwarding is disabled ==\n"
		if [[ "$(sysctl net.ipv4.ip_forward)" = "net.ipv4.ip_forward = 0" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify output matches:
		# sysctl net.ipv4.ip_forward
		net.ipv4.ip_forward = 0\n

		Remediation:
		Set the following parameter in the /etc/sysctl.conf file:
		net.ipv4.ip_forward = 0\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv4.ip_forward=0
		# sysctl -w net.ipv4.route.flush=1\n"

		fi
}

ensure_packet_redirect_sending_is_disabled () {
                echo -e "\e[92m== 3.1.2 Ensure packet redirect sending is disabled ==\n"
		if [[ "$(sysctl net.ipv4.conf.all.send_redirects)" = "net.ipv4.conf.all.send_redirects = 0" && "$(sysctl net.ipv4.conf.default.send_redirects)" = "net.ipv4.conf.default.send_redirects = 0" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify output matches:
		# sysctl net.ipv4.conf.all.send_redirects
		net.ipv4.conf.all.send_redirects = 0
		# sysctl net.ipv4.conf.default.send_redirects
		net.ipv4.conf.default.send_redirects = 0\n

		Remediation:
		Set the following parameters in the /etc/sysctl.conf file:
		net.ipv4.conf.all.send_redirects = 0
		net.ipv4.conf.default.send_redirects = 0\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv4.conf.all.send_redirects=0
		# sysctl -w net.ipv4.conf.default.send_redirects=0
		# sysctl -w net.ipv4.route.flush=1\n"

		fi
}

ensure_source_routed_packets_are_not_accepted () {
                echo -e "\e[92m== 3.2.1 Ensure source routed packets are not accepted ==\n"
		if [[ "$(sysctl net.ipv4.conf.all.accept_source_route)" = "net.ipv4.conf.all.accept_source_route = 0" && "$(sysctl net.ipv4.conf.default.accept_source_route)" = "net.ipv4.conf.default.accept_source_route = 0" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify output matches:
		# sysctl net.ipv4.conf.all.accept_source_route
		net.ipv4.conf.all.accept_source_route = 0
		# sysctl net.ipv4.conf.default.accept_source_route
		net.ipv4.conf.default.accept_source_route = 0\n

		Remediation:
		Set the following parameters in the /etc/sysctl.conf file:
		net.ipv4.conf.all.accept_source_route = 0
		net.ipv4.conf.default.accept_source_route = 0\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv4.conf.all.accept_source_route=0
		# sysctl -w net.ipv4.conf.default.accept_source_route=0
		# sysctl -w net.ipv4.route.flush=1\n"

		fi
}

ensure_icmp_redirects_are_not_accepted () {
                echo -e "\e[92m== 3.2.2 Ensure ICMP redirects are not accepted ==\n"
		if [[ "$(sysctl net.ipv4.conf.all.accept_redirects)" = "net.ipv4.conf.all.accept_redirects = 0" && "$(sysctl net.ipv4.conf.default.accept_redirects)" = "net.ipv4.conf.default.accept_redirects = 0" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify output matches:
		# sysctl net.ipv4.conf.all.accept_redirects
		net.ipv4.conf.all.accept_redirects = 0
		# sysctl net.ipv4.conf.default.accept_redirects
		net.ipv4.conf.default.accept_redirects = 0\n

		Remediation:
		Set the following parameters in the /etc/sysctl.conf file:
		net.ipv4.conf.all.accept_redirects = 0
		net.ipv4.conf.default.accept_redirects = 0\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv4.conf.all.accept_redirects=0
		# sysctl -w net.ipv4.conf.default.accept_redirects=0
		# sysctl -w net.ipv4.route.flush=1\n"

		fi
}

ensure_secure_icmp_redirects_are_not_accepted () {
                echo -e "\e[92m== 3.2.3 Ensure secure ICMP redirects are not accepted ==\n"
                if [[ "$(sysctl net.ipv4.conf.all.secure_redirects)" = "net.ipv4.conf.all.secure_redirects = 0" && "$(sysctl net.ipv4.conf.default.secure_redirects)" = "net.ipv4.conf.default.secure_redirects = 0" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:

		Run the following commands and verify output matches:
		# sysctl net.ipv4.conf.all.secure_redirects
		net.ipv4.conf.all.secure_redirects = 0
		# sysctl net.ipv4.conf.default.secure_redirects
		net.ipv4.conf.default.secure_redirects = 0\n

		Remediation:
		Set the following parameters in the /etc/sysctl.conf file:
		net.ipv4.conf.all.secure_redirects = 0
		net.ipv4.conf.default.secure_redirects = 0\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv4.conf.all.secure_redirects=0
		# sysctl -w net.ipv4.conf.default.secure_redirects=0
		# sysctl -w net.ipv4.route.flush=1\n"

		fi

}

ensure_suspicious_packets_are_logged () {
                echo -e "\e[92m== 3.2.4 Ensure suspicious packets are logged ==\n"
		if [[ "$(sysctl net.ipv4.conf.all.log_martians)" = "net.ipv4.conf.all.log_martians = 1" && "$(sysctl net.ipv4.conf.default.log_martians)" = "net.ipv4.conf.default.log_martians = 1" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify output matches:
		# sysctl net.ipv4.conf.all.log_martians
		net.ipv4.conf.all.log_martians = 1
		# sysctl net.ipv4.conf.default.log_martians
		net.ipv4.conf.default.log_martians = 1\n

		Remediation:
		Set the following parameters in the /etc/sysctl.conf file:
		net.ipv4.conf.all.log_martians = 1
		net.ipv4.conf.default.log_martians = 1\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv4.conf.all.log_martians=1
		# sysctl -w net.ipv4.conf.default.log_martians=1
		# sysctl -w net.ipv4.route.flush=1\n"

		fi
}

ensure_broadcast_icmp_requests_are_ignored () {
                echo -e "\e[92m== 3.2.5 Ensure broadcast ICMP requests are ignored ==\n"
		if [[ "$(sysctl net.ipv4.icmp_echo_ignore_broadcasts)" = "net.ipv4.icmp_echo_ignore_broadcasts = 1" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify output matches:
		# sysctl net.ipv4.icmp_echo_ignore_broadcasts
		net.ipv4.icmp_echo_ignore_broadcasts = 1\n

		Remediation:
		Set the following parameter in the /etc/sysctl.conf file:
		net.ipv4.icmp_echo_ignore_broadcasts = 1\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
		# sysctl -w net.ipv4.route.flush=1\n"

		fi
}

ensure_bogus_icmp_responses_are_ignored () {
                echo -e "\e[92m== 3.2.6 Ensure bogus ICMP responses are ignored ==\n"
		if [[ "$(sysctl net.ipv4.icmp_ignore_bogus_error_responses)" = "net.ipv4.icmp_ignore_bogus_error_responses = 1" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify output matches:
		# sysctl net.ipv4.icmp_ignore_bogus_error_responses
		net.ipv4.icmp_ignore_bogus_error_responses = 1\n

		Remediation:
		Set the following parameter in the /etc/sysctl.conf file:
		net.ipv4.icmp_ignore_bogus_error_responses = 1\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
		# sysctl -w net.ipv4.route.flush=1\n"

		fi
}

ensure_reverse_path_filtering_is_enabled () {
                echo -e "\e[92m== 3.2.7 Ensure Reverse Path Filtering is enabled ==\n"
		if [[ "$(sysctl net.ipv4.conf.all.rp_filter)" = "net.ipv4.conf.all.rp_filter = 1" && "$(sysctl net.ipv4.conf.default.rp_filter)" = "net.ipv4.conf.default.rp_filter = 1" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify output matches:
		# sysctl net.ipv4.conf.all.rp_filter
		net.ipv4.conf.all.rp_filter = 1
		# sysctl net.ipv4.conf.default.rp_filter
		net.ipv4.conf.default.rp_filter = 1\n

		Remediation:
		Set the following parameters in the /etc/sysctl.conf file:
		net.ipv4.conf.all.rp_filter = 1
		net.ipv4.conf.default.rp_filter = 1\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv4.conf.all.rp_filter=1
		# sysctl -w net.ipv4.conf.default.rp_filter=1
		# sysctl -w net.ipv4.route.flush=1\n"

		fi

}

ensure_tcp_syn_cookies_is_enabled () {
                echo -e "\e[92m== 3.2.8 Ensure TCP SYN Cookies is enabled ==\n"
		if [[ "$(sysctl net.ipv4.tcp_syncookies)" = "net.ipv4.tcp_syncookies = 1" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify output matches:
		# sysctl net.ipv4.tcp_syncookies
		net.ipv4.tcp_syncookies = 1\n

		Remediation:
		Set the following parameter in the /etc/sysctl.conf file:
		net.ipv4.tcp_syncookies = 1\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv4.tcp_syncookies=1
		# sysctl -w net.ipv4.route.flush=1\n"

		fi
}

ensure_ipv6_router_advertisements_are_not_accepted () {
                echo -e "\e[92m== 3.3.1 Ensure IPv6 router advertisements are not accepted (Not Scored) ==\n"
		if [[ "$(sysctl net.ipv6.conf.all.accept_ra)" = "net.ipv6.conf.all.accept_ra = 0" && "$(sysctl net.ipv6.conf.default.accept_ra)" = "net.ipv6.conf.default.accept_ra = 0" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify output matches:
		# sysctl net.ipv6.conf.all.accept_ra
		net.ipv6.conf.all.accept_ra = 0
		# sysctl net.ipv6.conf.default.accept_ra
		net.ipv6.conf.default.accept_ra = 0\n

		Remediation:
		Set the following parameters in the /etc/sysctl.conf file:
		net.ipv6.conf.all.accept_ra = 0
		net.ipv6.conf.default.accept_ra = 0\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv6.conf.all.accept_ra=0
		# sysctl -w net.ipv6.conf.default.accept_ra=0
		# sysctl -w net.ipv6.route.flush=1\n"

		fi
}

ensure_ipv6_redirects_are_not_accepted () {
                echo -e "\e[92m== 3.3.2 Ensure IPv6 redirects are not accepted ==\n"
		if [[ "$(sysctl net.ipv6.conf.all.accept_redirects)" = "net.ipv6.conf.all.accept_redirect = 0" && "$(sysctl net.ipv6.conf.default.accept_redirects)" = "net.ipv6.conf.default.accept_redirect = 0" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify output matches:
		# sysctl net.ipv6.conf.all.accept_redirects
		net.ipv6.conf.all.accept_redirect = 0
		# sysctl net.ipv6.conf.default.accept_redirects
		net.ipv6.conf.default.accept_redirect = 0\n

		Remediation:
		Set the following parameters in the /etc/sysctl.conf file:
		net.ipv6.conf.all.accept_redirect = 0
		net.ipv6.conf.default.accept_redirect = 0\n

		Run the following commands to set the active kernel parameters:
		# sysctl -w net.ipv6.conf.all.accept_redirects=0
		# sysctl -w net.ipv6.conf.default.accept_redirects=0
		# sysctl -w net.ipv6.route.flush=1\n"

		fi

}

ensure_ipv6_is_disabled () {
                echo -e "\e[92m== 3.3.3 Ensure IPv6 is disabled (Not Scored) ==\n"
		if [[ "$(grep GRUB_CMDLINE_LINUX /etc/default/grub 2>/dev/null)" =~ GRUB_CMDLINE_LINUX=.+?ipv6.disable=1 ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that each linux line has the 'ipv6.disable=1' parameter set:
		# grep "^\s*linux" /boot/grub/grub.cfg\n

		Remediation:
		Edit /etc/default/grub and add 'ipv6.disable=1' to GRUB_CMDLINE_LINUX:
		GRUB_CMDLINE_LINUX=\"ipv6.disable=1\"\n

		Run the following command to update the grub2 configuration:
		# update-grub\n"

		fi

}

ensure_tcp_wrappers_is_installed () {
                echo -e "\e[92m== 3.4.1 Ensure TCP Wrappers is installed ==\n"
		if [[ "$(dpkg -s tcpd 2>/dev/null | grep Status)" = "" || "$(dpkg -s tcpd 2>/dev/null | grep Status)" =~ ^Status:.install* ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify TCP Wrappers is installed:
		dpkg -s tcpd\n

		Remediation:
		Run the following command to install TCP Wrappers:
		apt-get install tcpd\n

		Notes:
		To verify if a service supports TCP Wrappers, run the following command:
		# ldd <path-to-daemon> | grep libwrap.so\n

		If there is any output, then the service supports TCP Wrappers.\n"

		fi

}

ensure_etc_hosts_allow_is_configured () {
                echo -e "\e[92m== 3.4.2 Ensure /etc/hosts.allow is configured ==\n"
		echo -e "Verify the following output from the /etc/hosts.allow file and ensure that the correct IPs are permitted to access the system:\n"
		echo -e "==\n"
		cat /etc/hosts.allow
		echo -e "==\n"
                echo -e "\e[31m		Audit:\n
		Run the following command and verify the contents of the /etc/hosts.allow file:
		# cat /etc/hosts.allow\n

		Remediation:
		Run the following command to create /etc/hosts.allow:
		# echo \"ALL: <net>/<mask>, <net>/<mask>, ...\" >/etc/hosts.allow
		where each <net>/<mask> combination (for example, \"192.168.1.0/255.255.255.0\") represents one network block in use by your organization that requires access to this system.
		Notes:
		Contents of the /etc/hosts.allow file will vary depending on your network configuration.\n"

}

ensure_etc_hosts_deny_is_configured () {
                echo -e "\e[92m== 3.4.3 Ensure /etc/hosts.deny is configured ==\n"
                if [[ "$(grep -v \# /etc/hosts.deny | egrep -v "^$" 2>/dev/null)" = "ALL: ALL" ]]
                then echo -e "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify the contents of the /etc/hosts.deny file:
		# cat /etc/hosts.deny
		ALL: ALL\n

		Remediation:
		Run the following command to create /etc/hosts.deny:
		# echo "ALL: ALL" >> /etc/hosts.deny\n

		Notes:
		Contents of the /etc/hosts.deny file may include additional options depending on your network configuration.\n"

		fi
}

ensure_permissions_on_etc_hosts_allow_are_configured () {
                echo -e "\e[92m== 3.4.4 Ensure permissions on /etc/hosts.allow are configured ==\n"
		if [[ "$(stat -c %a /etc/hosts.allow 2>/dev/null)" = "644" && "$(stat -c %U:%G /etc/hosts.allow 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify Uid and Gid are both 0/root and Access is 644:
		# stat /etc/hosts.allow
		Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)\n

		Remediation:
		Run the following commands to set permissions on /etc/hosts.allow:

		# chown root:root /etc/hosts.allow
		# chmod 644 /etc/hosts.allow\n"

		fi
}

ensure_permissions_on_etc_hosts_deny () {
                echo -e "\e[92m== 3.4.5 Ensure permissions on /etc/hosts.deny are 644 ==\n"
                if [[ "$(stat -c %a /etc/hosts.deny 2>/dev/null)" = "644" && "$(stat -c %U:%G /etc/hosts.deny 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify Uid and Gid are both 0/root and Access is 644:
		# stat /etc/hosts.deny
		Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)\n

		Remediation:
		Run the following commands to set permissions on /etc/hosts.deny:
		# chown root:root /etc/hosts.deny
		# chmod 644 /etc/hosts.deny\n"

		fi

}

ensure_dccp_is_disabled () {
                echo -e "\e[92m== 3.5.1 Ensure DCCP is disabled (Not Scored) ==\n"
                if [[ "$(modprobe -n -v dccp 2>/dev/null)" =~ install./bin/true && "$(lsmod | grep dccp)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify the output is as indicated:
		# modprobe -n -v dccp
		install /bin/true
		# lsmod | grep dccp
		<No output>\n

		Remediation:
		Edit or create the file /etc/modprobe.d/CIS.conf and add the following line:
		install dccp /bin/true\n"

		fi
}

ensure_sctp_is_disabled () {
                echo -e "\e[92m== 3.5.2 Ensure SCTP is disabled (Not Scored) ==\n"
		if [[ "$(modprobe -n -v sctp 2>/dev/null)" =~ install./bin/true && "$(lsmod | grep sctp)" = "" ]]
                then echo -e "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify the output is as indicated:
		# modprobe -n -v sctp
		install /bin/true
		# lsmod | grep sctp
		<No output>\n

		Remediation:
		Edit or create the file /etc/modprobe.d/CIS.conf and add the following line:
		install sctp /bin/true\n"

		fi
}

ensure_rds_is_disabled () {
                echo -e "\e[92m== 3.5.3 Ensure RDS is disabled (Not Scored) ==\n"
                if [[ "$(modprobe -n -v rds 2>/dev/null)" =~ install./bin/true && "$(lsmod | grep rds)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following commands and verify the output is as indicated:
                # modprobe -n -v rds
                install /bin/true
                # lsmod | grep rds
                <No output>\n

                Remediation:
                Edit or create the file /etc/modprobe.d/CIS.conf and add the following line:
                install rds /bin/true\n"

                fi
}

ensure_tipc_is_disabled () {
                echo -e "\e[92m== 3.5.4 Ensure TIPC is disabled (Not Scored) ==\n"
                if [[ "$(modprobe -n -v tipc 2>/dev/null)" =~ install./bin/true && "$(lsmod | grep tipc)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following commands and verify the output is as indicated:
                # modprobe -n -v tipc
                install /bin/true
                # lsmod | grep tipc
                <No output>\n

                Remediation:
                Edit or create the file /etc/modprobe.d/CIS.conf and add the following line:
                install tipc /bin/true\n"

                fi
}

ensure_iptables_is_installed () {
                echo -e "\e[92m== 3.6.1 Ensure iptables is installed ==\n"
		if [[ "$(dpkg -s iptables 2>/dev/null | grep Status)" =~ "Status: install ok" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify iptables is installed:
		# dpkg -s iptables\n

		Remediation:
		Run the following command to install iptables: # apt-get install iptables\n"

		fi
}

ensure_default_deny_firewall_policy () {
                echo -e "\e[92m== 3.6.2 Ensure default deny firewall policy ==\n"
		mapfile -t my_array < <( iptables -L | grep Chain )
		for rule in "${my_array[@]}"
		do
			if [[ $rule =~ Chain.+policy.DROP ]]
			then echo -e "Passed!"
			else
                	echo -e "\e[31mFailed!\e[0m : \n                Audit:
			Run the following command and verify that the policy for the INPUT, OUTPUT, and FORWARD chains is DROP or REJECT:
			# iptables -L
			Chain INPUT (policy DROP)
			Chain FORWARD (policy DROP)
			Chain OUTPUT (policy DROP)\n

			Remediation:
			Run the following commands to implement a default DROP policy:
			# iptables -P INPUT DROP
			# iptables -P OUTPUT DROP
			# iptables -P FORWARD DROP\n

			Notes:
			Changing firewall settings while connected over network can result in being locked out of the system.
			Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well.\n"

			break

			fi

		done

}

ensure_looopback_traffic_is_configured () {
                echo -e "\e[92m== 3.6.3 Ensure loopback traffic is configured ==\n"
		echo -e "\e[31m==\n"
		iptables -L INPUT -v -n
		echo -e "==\n"
		echo -e "Verify the output above matches this:\n

		# iptables -L INPUT -v -n
		Chain INPUT (policy DROP 0 packets, 0 bytes)
		pkts bytes target	prot opt in     out	source		destination
		   0    0  ACCEPT	all  --  lo	*	0.0.0.0/0	0.0.0.0/0
		   0	0  DROP		all  --  *      *	127.0.0.0/8	0.0.0.0/0"

                echo -e "==\n"
		iptables -L OUTPUT -v -n
                echo -e "==\n"
                echo -e "Verify the output above matches this:\n

		# iptables -L OUTPUT -v -n
		Chain OUTPUT (policy DROP 0 packets, 0 bytes)
                pkts bytes target       prot opt in     out     source          destination
		   0	0  ACCEPT	all  --  *	*	0.0.0.0/0	0.0.0.0/0\n

		Remediation:
		Run the following commands to implement the loopback rules:
		# iptables -A INPUT -i lo -j ACCEPT
		# iptables -A OUTPUT -o lo -j ACCEPT
		# iptables -A INPUT -s 127.0.0.0/8 -j DROP\n

		Notes:
		Changing firewall settings while connected over network can result in being locked out of the system.
		Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well.\n"

}

ensure_outbound_and_established_connections_are_configured () {
                echo -e "\e[92m== 3.6.4 Ensure outbound and established connections are configured (Not Scored) ==\n"
		echo -e "\e[31mVerify that all rules for new outbound, and established connections match site policy from the output below:\n"

                echo -e "==\n"
		iptables -L -v -n
                echo -e "==\n"

		echo -e "Remediation:
		Configure iptables in accordance with site policy. The following commands will implement a policy to allow all outbound connections and all established connections:
		# iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
		# iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
		# iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
		# iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
		# iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
		# iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

		Notes:
		Changing firewall settings while connected over network can result in being locked out of the system.
		Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well.\n"
}

ensure_firewall_rules_exist_for_all_open_ports () {
                echo -e "\e[92m== 3.6.5 Ensure firewall rules exist for all open ports ==\n"
		echo -e "\e[31mThe following shows the open ports on the server:\n"
		echo -e "==\n"
		netstat -napt | grep LISTEN
		echo -e "\n"
		echo -e "==\n"

		echo -e "The following shows the current firewall rules:\n"
                echo -e "==\n"
		iptables -L INPUT -v -n
		echo -e "\n"
                echo -e "==\n"

		echo -e "		Verify all open ports listening on non-localhost addresses have at least one firewall rule.
		The last line identified by the "tcp dpt:22 state NEW" identifies it as a firewall rule for new connections on tcp port 22.\n

		Remediation:
		For each port identified in the audit which does not have a firewall rule establish a proper rule for accepting inbound connections:
		iptables -A INPUT -p <protocol> --dport <port> -m state --state NEW -j ACCEPT\n

		Notes:
		Changing firewall settings while connected over network can result in being locked out of the system.
		Remediation will only affect the active system firewall, be sure to configure the default policy in your firewall management to apply on boot as well.
		The remediation command opens up the port to traffic from all sources. Consult iptables documentation and set any restrictions in compliance with site policy.\n"
}

ensure_wireless_interfaces_are_disabled () {
                echo -e "\e[92m== 3.7 Ensure wireless interfaces are disabled (Not Scored) ==\n"
		if [[ "$(iwconfig 2>/dev/null)" = "" ]]
                then echo -e "Passed!\n"
                else
		echo -e "\e[31mVerify that all wireless interfaces are disabled from the output below:\n"
		echo -e "==\n"
		ip link show up
		echo -e "\n"
                echo -e "==\n"

		echo -e "		Remediation:
		Run the following command to disable any wireless interfaces:
		# ip link set <interface> down
		Disable any wireless interfaces in your network configuration.

		Impact:
		Many if not all laptop workstations and some desktop workstations will connect via wireless requiring these interfaces be enabled.\n"

		fi
}

ensure_audit_log_storage_size_is_configured () {
                echo -e "\e[92m== 4.1.1.1 Configure Data Retention ==\n"
		echo -e "\e[31mEnsure that that following output for the max auditd log file size is configured in the output below from /etc/audit/auditd.conf:"
		echo -e "===\n"
		if [[ "$(grep ^max_log_file.\= /etc/audit/auditd.conf 2>/dev/null)" = "" ]]
		then echo -e "/etc/audit/auditd.conf does not exist or does not contain a max_log_file directive\n"
		else
		grep ^max_log_file.= /etc/audit/auditd.conf 2>/dev/null
		fi
		echo -e "===\n\e[0m"
		echo -e "		Audit:
		Run the following command and ensure output is in compliance with site policy:
		# grep max_log_file /etc/audit/auditd.conf
		max_log_file = <MB>\n

		Remediation:
		Set the following parameter in /etc/audit/auditd.conf in accordance with site policy:
		max_log_file = <MB>\n

		Notes:
		The max_log_file parameter is measured in megabytes.\n"

}

ensure_system_is_disabled_when_audit_logs_are_full() {
                echo -e "\e[92m== 4.1.1.2 Ensure system is disabled when audit logs are full ==\n"
		if [[ "$(grep space_left_action /etc/audit/auditd.conf 2>/dev/null)" = "space_left_action = email" && "$(grep action_mail_acct /etc/audit/auditd.conf 2>/dev/null)" = "action_mail_acct = root" && "$(grep admin_space_left_action /etc/audit/auditd.conf 2>/dev/null)" = "admin_space_left_action = halt" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify output matches:
		# grep space_left_action /etc/audit/auditd.conf
		space_left_action = email
		# grep action_mail_acct /etc/audit/auditd.conf
		action_mail_acct = root
		# grep admin_space_left_action /etc/audit/auditd.conf
		admin_space_left_action = halt\n

		Remediation:
		Set the following parameters in /etc/audit/auditd.conf:]
		space_left_action = email
		action_mail_acct = root
		admin_space_left_action = halt\n"

		fi

}

ensure_audit_logs_are_not_automatically_deleted () {
                echo -e "\e[92m== 4.1.1.3 Ensure audit logs are not automatically deleted ==\n"
		if [[ "$(grep ^max_log_file_action /etc/audit/auditd.conf 2>/dev/null)" = "max_log_file_action = keep_logs" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify output matches:
		# grep max_log_file_action /etc/audit/auditd.conf
		max_log_file_action = keep_logs\n

		Remediation:
		Set the following parameter in /etc/audit/auditd.conf:
		max_log_file_action = keep_logs\n"

		fi
}

ensure_auditd_service_is_enabled () {
                echo -e "\e[92m== 4.1.2 Ensure auditd service is enabled ==\n"
                if [[ "$(systemctl is-enabled auditd 2>/dev/null)" = "enabled" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify auditd is enabled:
		# systemctl is-enabled auditd
		enabled\n

		Verify result is \"enabled\".

		Remediation:
		Run the following command to enable auditd:
		# systemctl enable auditd\n"

		fi
}

ensure_auditing_for_processes_that_start_prior_to_auditd_is_enabled () {
                echo -e "\e[92m== 4.1.3 Ensure auditing for processes that start prior to auditd is enabled ==\n"
		if [[ "$(grep GRUB_CMDLINE_LINUX /etc/default/grub 2>/dev/null)" =~ GRUB_CMDLINE_LINUX.+audit=1 ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that each linux line has the audit=1 parameter set:
		# grep "^\s*linux" /boot/grub/grub.cfg\n

		Remediation:
		Edit /etc/default/grub and add audit=1 to GRUB_CMDLINE_LINUX:
		GRUB_CMDLINE_LINUX=\"audit=1\"\n

		Run the following command to update the grub2 configuration:
		# update-grub

		Notes:
		This recommendation is designed around the grub bootloader, if LILO or another bootloader is in use in your environment enact equivalent settings.\n"

		fi

}

ensure_events_that_modify_date_and_time_info_are_collected () {
                echo -e "\e[92m== 4.1.4 Ensure events that modify date and time information are collected ==\n"
		echo -e "\e[31m===\n"
		if [[ "$(grep time-change /etc/audit/audit.rules 2>/dev/null)" = "" ]]
		then
		echo -e "/etc/audit/audit.rules does not exist or does not contain the time-change directive\n"
		else
		grep time-change /etc/audit/audit.rules 2>/dev/null
		fi
		echo -e "===\e[0m\n"

		echo -e "		Audit:
		On a 32 bit system run the following command and verify the output matches:
		# grep time-change /etc/audit/audit.rules
		-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
		-a always,exit -F arch=b32 -S clock_settime -k time-change
		-w /etc/localtime -p wa -k time-change\n

		On a 64 bit system run the following command and verify the output matches:
		# grep time-change /etc/audit/audit.rules
		-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
		-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
		-a always,exit -F arch=b64 -S clock_settime -k time-change
		-a always,exit -F arch=b32 -S clock_settime -k time-change
		-w /etc/localtime -p wa -k time-change\n

		Remediation:
		For 32 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
		-a always,exit -F arch=b32 -S clock_settime -k time-change
		-w /etc/localtime -p wa -k time-change

		For 64 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
		-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
		-a always,exit -F arch=b64 -S clock_settime -k time-change
		-a always,exit -F arch=b32 -S clock_settime -k time-change
		-w /etc/localtime -p wa -k time-change\n"


}

ensure_events_that_modify_user_group_info_are_collected () {
                echo -e "\e[92m== 4.1.5 Ensure events that modify user/group information are collected ==\n"
                echo -e "\e[31m===\n"
                if [[ "$(grep identity /etc/audit/audit.rules 2>/dev/null)" = "" ]]
                then
                echo -e "/etc/audit/audit.rules does not exist or does not contain the identity directive\n"
                else
                grep identity /etc/audit/audit.rules 2>/dev/null
                fi
                echo -e "===\e[0m\n"

                echo -e "               Audit:
		Run the following command and verify output matches:
		# grep identity /etc/audit/audit.rules
		-w /etc/group -p wa -k identity
		-w /etc/passwd -p wa -k identity
		-w /etc/gshadow -p wa -k identity
		-w /etc/shadow -p wa -k identity
		-w /etc/security/opasswd -p wa -k identity\n

		Remediation:
		Add the following lines to the /etc/audit/audit.rules file:
		-w /etc/group -p wa -k identity
		-w /etc/passwd -p wa -k identity
		-w /etc/gshadow -p wa -k identity
		-w /etc/shadow -p wa -k identity
		-w /etc/security/opasswd -p wa -k identity\n"

}

ensure_events_that_modify_the_systems_network_env_are_collected () {
                echo -e "\e[92m== 4.1.6 Ensure events that modify the system's network environment are collected ==\n"
                echo -e "\e[31m===\n"
                if [[ "$(grep system-locale /etc/audit/audit.rules 2>/dev/null)" = "" ]]
                then
                echo -e "/etc/audit/audit.rules does not exist or does not contain the system-locale directive\n"
                else
                grep system-locale /etc/audit/audit.rules 2>/dev/null
                fi
                echo -e "===\e[0m\n"

                echo -e "               Audit:
		On a 32 bit system run the following command and verify the output matches:
		# grep system-locale /etc/audit/audit.rules
		-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
		-w /etc/issue -p wa -k system-locale
		-w /etc/issue.net -p wa -k system-locale
		-w /etc/hosts -p wa -k system-locale
		-w /etc/network -p wa -k system-locale
		-w /etc/networks -p wa -k system-locale\n

		On a 64 bit system run the following command and verify the output matches:
		# grep system-locale /etc/audit/audit.rules
		-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
		-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
		-w /etc/issue -p wa -k system-locale
		-w /etc/issue.net -p wa -k system-locale
		-w /etc/hosts -p wa -k system-locale
		-w /etc/network -p wa -k system-locale
		-w /etc/networks -p wa -k system-locale\n

		Remediation:
		For 32 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
		-w /etc/issue -p wa -k system-locale
		-w /etc/issue.net -p wa -k system-locale
		-w /etc/hosts -p wa -k system-locale
		-w /etc/network -p wa -k system-locale
		-w /etc/networks -p wa -k system-locale\n

		For 64 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
		-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
		-w /etc/issue -p wa -k system-locale
		-w /etc/issue.net -p wa -k system-locale
		-w /etc/hosts -p wa -k system-locale
		-w /etc/network -p wa -k system-locale
		-w /etc/networks -p wa -k system-locale\n"
}

ensure_events_that_modify_the_systems_manditory_access_controls_are_collected () {
                echo -e "\e[92m== 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected ==\n"
                echo -e "\e[31m===\n"
                if [[ "$(grep MAC-policy /etc/audit/audit.rules 2>/dev/null)" = "" ]]
                then
                echo -e "/etc/audit/audit.rules does not exist or does not contain the MAC-policy directive\n"
                else
                grep MAC-policy /etc/audit/audit.rules 2>/dev/null
                fi
                echo -e "===\e[0m\n"

                echo -e "               Audit:
		On systems using SELinux run the following command and verify output matches:
		# grep MAC-policy /etc/audit/audit.rules
		-w /etc/selinux/ -p wa -k MAC-policy\n

		On systems using AppArmor run the following command and verify output matches:
		# grep MAC-policy /etc/audit/audit.rules
		-w /etc/apparmor/ -p wa -k MAC-policy
		-w /etc/apparmor.d/ -p wa -k MAC-policy

		Remediation:
		On systems using SELinux add the following line to the /etc/audit/audit.rules file:
		-w /etc/selinux/ -p wa -k MAC-policy\n

		On systems using AppArmor add the following line to the /etc/audit/audit.rules file:
		-w /etc/apparmor/ -p wa -k MAC-policy
		-w /etc/apparmor.d/ -p wa -k MAC-policy\n"

}

ensure_login_and_logout_events_are_collected () {
                echo -e "\e[92m== 4.1.8 Ensure login and logout events are collected ==\n"
		if [[ "$(grep logins /etc/audit/audit.rules 2>/dev/null)" != "" && "$(grep logins /etc/audit/audit.rules 2>/dev/null | grep faillog)" = "-w /var/log/faillog -p wa -k logins" && "$(grep logins /etc/audit/audit.rules 2>/dev/null | grep lastlog)" = "-w /var/log/lastlog -p wa -k logins" && "$(grep logins /etc/audit/audit.rules 2>/dev/null | grep tallylog)" = "-w /var/log/tallylog -p wa -k logins" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify output matches:
		# grep logins /etc/audit/audit.rules
		-w /var/log/faillog -p wa -k logins
		-w /var/log/lastlog -p wa -k logins
		-w /var/log/tallylog -p wa -k logins\n

		Remediation:
		Add the following lines to the /etc/audit/audit.rules file:
		-w /var/log/faillog -p wa -k logins
		-w /var/log/lastlog -p wa -k logins
		-w /var/log/tallylog -p wa -k logins\n"

		fi
}

ensure_session_initiation_information_is_collected () {
                echo -e "\e[92m== 4.1.9 Ensure session initiation information is collected ==\n"
		if [[ "$(grep session /etc/audit/audit.rules 2>/dev/null | grep utmp)" =~ /var/run/utmp.+wa.+session && "$(grep session /etc/audit/audit.rules 2>/dev/null | grep wtmp)" =~ /var/log/wtmp.+wa.+session && "$(grep session /etc/audit/audit.rules 2>/dev/null | grep btmp)" =~ /var/log/btmp.+wa.+session ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify output matches:
		# grep session /etc/audit/audit.rules
		-w /var/run/utmp -p wa -k session
		-w /var/log/wtmp -p wa -k session
		-w /var/log/btmp -p wa -k session\n

		Remediation:
		Add the following lines to the /etc/audit/audit.rules file:
		-w /var/run/utmp -p wa -k session
		-w /var/log/wtmp -p wa -k session
		-w /var/log/btmp -p wa -k session\n

		Notes:
		The last command can be used to read /var/log/wtmp (last with no parameters) and /var/run/utmp (last -f /var/run/utmp)\n"

		fi

}

ensure_discretionary_access_control_permission_mod_events_are_collected () {
                echo -e "\e[92m== 4.1.10 Ensure discretionary access control permission modification events are collected ==\n"
                if [[ "$(grep perm_mod /etc/audit/audit.rules 2>/dev/null | grep fchmodat | head -1)" =~ \-a.always,exit.-F.arch=b(32|64).-S.chmod.-S.fchmod.-S.fchmodat.-F.auid.=1000.-F.auid!=4294967295.-k.perm_mod  && "$(grep perm_mod /etc/audit/audit.rules 2>/dev/null | grep fchownat | head -1)" =~ -a.always,exit.-F.arch=b...-S.chown.-S.fchown.-S.fchownat.-S.lchown.-F.auid.=1000.-F.auid!=4294967295.-k.perm_mod ]]
		then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		On a 32 bit system run the following command and verify the output matches:
		# grep perm_mod /etc/audit/audit.rules
		-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod\n

		On a 64 bit system run the following command and verify the output matches:
		# grep perm_mod /etc/audit/audit.rules
		-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod\n

		Remediation:
		For 32 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod\n

		For 64 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
		-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod\n"


		fi
}

ensure_unsuccessful_unauthorized_file_access_attempts_are_collected () {
                echo -e "\e[92m== 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected ==\n"
		if [[ "$(grep access /etc/audit/audit.rules 2>/dev/null | grep EACCES | grep access)" =~  a.always,exit.+?EACCES..F.+?access && "$(grep access /etc/audit/audit.rules 2>/dev/null | grep EPERM | grep access)" =~ a.always,exit.+?EPERM..F.+?access ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		On a 32 bit system run the following command and verify the output matches:
		# grep access /etc/audit/audit.rules
		-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
		-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access\n

		On a 64 bit system run the following command and verify the output matches:
		# grep access /etc/audit/audit.rules
		-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
		-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
		-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
		-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access\n

		Remediation:
		For 32 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
		-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access\n

		For 64 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
		-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
		-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
		-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access\n"

		fi

}

ensure_use_of_privileged_commands_is_collected () {
                echo -e "\e[92m== 4.1.12 Ensure use of privileged commands is collected ==\n"
		echo -e "Verify that the lines from the output below are in the /etc/audit/audit.rules file:\n"

		echo -e "\e[31m===\n"
		for partition in $(df -h | awk '{print $6}' | egrep -v "Mounted|/dev|/run|/cgroup")
			do
			find $partition -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }'
			done
		echo -e "\n===\e[0m\n"

		echo -e "Contents of the /etc/audit/audit.rules file:\n"
		echo -e "\e[31m===\n"
		cat /etc/audit/audit.rules
		echo -e "\n===\e[0m\n

		Remediation:
		To remediate this issue, the system administrator will have to execute a find command to locate all the privileged programs and then add an audit line for each one of them. The audit parameters associated with this are as follows:
		-F path=\" $1 \" - will populate each file name found through the find command and processed by awk.
		-F perm=x - will write an audit record if the file is executed.
		-F auid>=1000 - will write a record if the user executing the command is not a privileged user.
		-F auid!= 4294967295 - will ignore Daemon events
		All audit records should be tagged with the identifier \"privileged\".\n

		Run the following command replacing <partition> with a list of partitions where programs can be executed from on your system:
		# find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \"-a always,exit -F path=\" $1 \" -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged\" }'\n
		Add all resulting lines to the /etc/audit/audit.rules file.\n"

}

ensure_successful_file_system_mounts_are_collected () {
                echo -e "\e[92m== 4.1.13 Ensure successful file system mounts are collected ==\n"
		if [[ "$(grep mounts /etc/audit/audit.rules 2>/dev/null)" =~ \-a.always,exit.-F.arch.+?k.mounts ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		On a 32 bit system run the following command and verify the output matches:
		# grep mounts /etc/audit/audit.rules
		-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

		On a 64 bit system run the following command and verify the output matches:
		# grep mounts /etc/audit/audit.rules
		-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
		-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

		Remediation:
		For 32 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

		For 64 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
		-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

		Notes:
		This tracks successful and unsuccessful mount commands. File system mounts do not have to come from external media and this action still does not verify write (e.g. CD ROMS).\n"

		fi

}

ensure_file_deletion_events_by_users_are_collected () {
                echo -e "\e[92m== 4.1.14 Ensure file deletion events by users are collected ==\n"
		if [[ "$(grep delete /etc/audit/audit.rules 2>/dev/null)" =~ \-a.always,exit.+?arch.+delete ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		On a 32 bit system run the following command and verify the output matches:
		# grep delete /etc/audit/audit.rules
		-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete\n

		On a 64 bit system run the following command and verify the output matches:
		# grep delete /etc/audit/audit.rules
		-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
		-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete\n

		Remediation:
		For 32 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

		For 64 bit systems add the following lines to the /etc/audit/audit.rules file:
		-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
		-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete\n

		Notes:
		At a minimum, configure the audit system to collect file deletion events for all users and root.\n"

		fi
}

ensure_changes_to_system_administration_scope_is_collected () {
                echo -e "\e[92m== 4.1.15 Ensure changes to system administration scope (sudoers) is collected ==\n"
		if [[ "$(grep scope /etc/audit/audit.rules 2>/dev/null | grep "sudoers ")" = "-w /etc/sudoers -p wa -k scope" && "$(grep scope /etc/audit/audit.rules 2>/dev/null | grep "sudoers.d")" = "-w /etc/sudoers.d -p wa -k scope" ]]
                then echo -e "Passed!\n"
		else
		echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify output matches:
		# grep scope /etc/audit/audit.rules
		-w /etc/sudoers -p wa -k scope
		-w /etc/sudoers.d -p wa -k scope\n

		Remediation:
		Add the following line to the /etc/audit/audit.rules file:
		-w /etc/sudoers -p wa -k scope
		-w /etc/sudoers.d -p wa -k scope\n"

		fi

}

ensure_system_administrator_actions_sudolog_are_collected () {
                echo -e "\e[92m== 4.1.16 Ensure system administrator actions (sudolog) are collected ==\n"
		if [[ "$(grep actions /etc/audit/audit.rules 2>/dev/null | grep sudo.log)" = "-w /var/log/sudo.log -p wa -k actions" ]]
                then echo -e "Passed!\n"
		else
		echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify output matches:
		# grep actions /etc/audit/audit.rules
		-w /var/log/sudo.log -p wa -k actions\n

		Remediation:
		Add the following lines to the /etc/audit/audit.rules file: \n
		-w /var/log/sudo.log -p wa -k actions\n

		Notes:
		The system must be configured with su disabled (See Item 5.6 Ensure access to the su command is restricted) to force all command execution through sudo. This will not be effective on the console, as administrators can log in as root.\n"

		fi
}

ensure_kernel_module_loading_and_unloading_is_collected () {
                echo -e "\e[92m== 4.1.17 Ensure kernel module loading and unloading is collected ==\n"
		if [[ "$(grep modules /etc/audit/audit.rules 2>/dev/null | grep insmod)" = "-w /sbin/insmod -p x -k modules" && "$(grep modules /etc/audit/audit.rules 2>/dev/null | grep rmmod)" = "-w /sbin/rmmod -p x -k modules" && "$(grep modules /etc/audit/audit.rules 2>/dev/null | grep modprobe)" = "-w /sbin/modprobe -p x -k modules" && "$(grep modules /etc/audit/audit.rules 2>/dev/null | grep delete_module)" =~ -a.always,exit.arch.+?delete_module.-k.modules ]]
                then echo -e "Passed!\n"
		else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		On a 32 bit system run the following command and verify the output matches:
		# grep modules /etc/audit/audit.rules
		-w /sbin/insmod -p x -k modules
		-w /sbin/rmmod -p x -k modules
		-w /sbin/modprobe -p x -k modules
		-a always,exit arch=b32 -S init_module -S delete_module -k modules\n

		On a 64 bit system run the following command and verify the output matches:
		# grep modules /etc/audit/audit.rules
		-w /sbin/insmod -p x -k modules
		-w /sbin/rmmod -p x -k modules
		-w /sbin/modprobe -p x -k modules
		-a always,exit arch=b64 -S init_module -S delete_module -k modules\n

		For 32 bit systems add the following lines to the /etc/audit/audit.rules file:
		-w /sbin/insmod -p x -k modules
		-w /sbin/rmmod -p x -k modules
		-w /sbin/modprobe -p x -k modules
		-a always,exit arch=b32 -S init_module -S delete_module -k modules\n

		For 64 bit systems add the following lines to the /etc/audit/audit.rules file:
		-w /sbin/insmod -p x -k modules
		-w /sbin/rmmod -p x -k modules
		-w /sbin/modprobe -p x -k modules
		-a always,exit arch=b64 -S init_module -S delete_module -k modules\n"
	fi

}

ensure_the_audit_configuration_is_immutable () {
                echo -e "\e[92m== 4.1.18 Ensure the audit configuration is immutable ==\n"
		if [[ "$(grep "^\s*[^#]" /etc/audit/audit.rules 2>/dev/null | tail -1)" = "-e 2" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify output matches:
		# grep "^\s*[^#]" /etc/audit/audit.rules | tail -1
		-e 2\n

		Remediation:
		Add the following line to the end of the/etc/audit/audit.rules file.
		-e 2\n"

	fi
}

ensure_rsyslog_service_is_enabled () {
		echo -e "\e[92m== 4.2.1.1 Ensure rsyslog Service is enabled ==\n"
		if [[ "$(systemctl is-enabled rsyslog 2>/dev/null)" = "enabled" ]]
        	then echo -e "Passed!\n"
        	else
        	echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify rsyslog is enabled:
		# systemctl is-enabled rsyslog
		enabled\n

		Verify result is \"enabled\".\n

		Remediation:
		Run the following command to enable rsyslog:
		systemctl enable rsyslog\n"

	fi
}

ensure_logging_is_configured () {
		echo -e "\e[92m== 4.2.1.2 Ensure logging is configured (Not Scored) ==\n"
		echo -e "Review the contents of /var/log below and verify that log files are logging information and they are not empty:\n"
		echo -e "\e[31m===\n"
		ls -l /var/log
		echo -e "\n===\n\e[0m"
		echo -e "\n		Audit:
		Review the contents of the /etc/rsyslog.conf file to ensure appropriate logging is set. In addition, run the following command and verify that the log files are logging information:
		# ls -l /var/log/\n

		Remediation:
		Edit the following lines in the /etc/rsyslog.conf file as appropriate for your environment:
		*.emerg
		mail.*
		mail.info
		mail.warning
		mail.err
		news.crit
		news.err
		news.notice
		*.=warning;*.=err
		*.crit
		*.*;mail.none;news.none
		local0,local1.*
		local2,local3.*
		local4,local5.*
		local6,local7.*
		 :omusrmsg:*
		 -/var/log/mail
		 -/var/log/mail.info
		 -/var/log/mail.warn
		 /var/log/mail.err
		 -/var/log/news/news.crit
		 -/var/log/news/news.err
		 -/var/log/news/news.notice
		 -/var/log/warn
		 /var/log/warn
		 -/var/log/messages
		 -/var/log/localmessages
		 -/var/log/localmessages
		 -/var/log/localmessages
		 -/var/log/localmessages\n

		 Run the following command to restart rsyslogd:
		 # pkill -HUP rsyslogd\n"


 }

 ensure_rsyslog_default_file_permissions_configured () {
		echo -e "\e[92m== 4.2.1.3 Ensure rsyslog default file permissions configured ==\n"
		if [[ "$(grep ^\$FileCreateMode /etc/rsyslog.conf 2>/dev/null)" =~ \$FileCreateMode.06[0,4]0 ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that $FileCreateMode is 0640 or more restrictive:
		# grep ^\$FileCreateMode /etc/rsyslog.conf\n

		Remediation:
		Edit the /etc/rsyslog.conf and set $FileCreateMode to 0640 or more restrictive: $FileCreateMode 0640\n"

	fi
}

ensure_rsyslog_is_configured_to_send_logs_to_remote_host () {
		echo -e "\e[92m== 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host ==\n"
		if [[ "$(grep "^*.*[^I][^I]*@" /etc/rsyslog.conf 2>/dev/null)" =~ ^\*\.\*.\@\@.+?$ ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Review the /etc/rsyslog.conf file and verify that logs are sent to a central host (where loghost.example.com is the name of your central log host):
		# grep "^*.*[^I][^I]*@" /etc/rsyslog.conf
		*.* @@loghost.example.com\n

		Remediation:
		Edit the /etc/rsyslog.conf file and add the following line (where loghost.example.com is the name of your central log host).
		*.* @@loghost.example.com
		Run the following command to restart rsyslog: # pkill -HUP rsyslogd\n"

	fi
}

ensure_remote_rsyslog_messages_are_only_accepted_on_designated_log_hosts () {
		echo -e "\e[92m== 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts ==\n"
		if [[ "$(grep '$ModLoad imtcp.so' /etc/rsyslog.conf 2>/dev/null)" = "$ModLoad imtcp.so" && "$(grep '$InputTCPServerRun' /etc/rsyslog.conf 2>/dev/null)" = "$InputTCPServerRun 514" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify the resulting lines are uncommented on designated log hosts and commented or removed on all others:
		# grep '$ModLoad imtcp.so' /etc/rsyslog.conf
		$ModLoad imtcp.so
		# grep '$InputTCPServerRun' /etc/rsyslog.conf
		$InputTCPServerRun 514\n

		Remediation:
		For hosts that are designated as log hosts, edit the /etc/rsyslog.conf file and un- comment or add the following lines:
		$ModLoad imtcp.so
		$InputTCPServerRun 514\n

		For hosts that are not designated as log hosts, edit the /etc/rsyslog.conf file and comment or remove the following lines:
		# $ModLoad imtcp.so
		# $InputTCPServerRun 514\n

		Run the following command to restart rsyslogd:
		# pkill -HUP rsyslogd\n"

	fi
}

ensure_syslog_ng_service_is_enabled () {
                echo -e "\e[92m== 4.2.2.1 Ensure syslog-ng service is enabled ==\n"
		if [[ "$(systemctl is-enabled syslog-ng 2>/dev/null)" = "enabled" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify syslog-ng is enabled:
		# systemctl is-enabled syslog-ng
		enabled\n

		Verify result is \"enabled\".\n

		Remediation:
		Run the following command to enable syslog-ng:
		# update-rc.d syslog-ng enable\n"

	fi
}

ensure_syslog_ng_logging_is_configured () {
		echo -e "\e[92m== 4.2.2.2 Ensure logging is configured (Not Scored) ==\n"
		echo -e "Review the contents of the /etc/syslog-ng/syslog-ng.conf file below to ensure appropriate logging is set. In addition, also verify that information is being logged to /var/log from the output below and ensure that the log files are logging information:\n"
		echo -e "\e[31m=== cat /etc/syslog-ng/syslog-ng.conf ===\n"
		cat /etc/syslog-ng/syslog-ng.conf
		echo -e "\n===\n\n\n"
		echo -e "=== ls -l /var/log ===\n"
		ls -l /var/log
		echo -e "\n===\n"

		echo -e "\e[0m		Audit:
		Review the contents of the /etc/syslog-ng/syslog-ng.conf file to ensure appropriate logging is set. In addition, run the following command and ensure that the log files are logging information:
		# ls -l /var/log/\n

		Remediation:
		Edit the log lines in the /etc/syslog-ng/syslog-ng.conf file as appropriate for your environment:
		log { source(src); source(chroots); filter(f_console); destination(console); };
		log { source(src); source(chroots); filter(f_console); destination(xconsole); };
		log { source(src); source(chroots); filter(f_newscrit); destination(newscrit); };
		log { source(src); source(chroots); filter(f_newserr); destination(newserr); };
		log { source(src); source(chroots); filter(f_newsnotice); destination(newsnotice); };
		log { source(src); source(chroots); filter(f_mailinfo); destination(mailinfo); };
		log { source(src); source(chroots); filter(f_mailwarn); destination(mailwarn); };
		log { source(src); source(chroots); filter(f_mailerr);  destination(mailerr); };
		log { source(src); source(chroots); filter(f_mail); destination(mail); };
		log { source(src); source(chroots); filter(f_acpid); destination(acpid); flags(final);
		};
		log { source(src); source(chroots); filter(f_acpid_full); destination(devnull);
		flags(final); };
		log { source(src); source(chroots); filter(f_acpid_old); destination(acpid);
		flags(final); };
		log { source(src); source(chroots); filter(f_netmgm); destination(netmgm);
		flags(final); };
		log { source(src); source(chroots); filter(f_local); destination(localmessages); };
		log { source(src); source(chroots); filter(f_messages); destination(messages); };
		log { source(src); source(chroots); filter(f_iptables); destination(firewall); };
		log { source(src); source(chroots); filter(f_warn); destination(warn); };\n

		Run the following command to restart syslog-ng:
		# pkill -HUP syslog-ng\n"

}

ensure_syslog_ng_default_file_permissions_configured () {
		echo -e "\e[92m== 4.2.2.3 Ensure syslog-ng default file permissions configured ==\n"
		if [[ "$(grep ^options /etc/syslog-ng/syslog-ng.conf 2>/dev/null)" = "options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };" ]]
                then echo -e "Passed!\n"
		else
		echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify the perm option is 0640 or more restrictive:
		# grep ^options /etc/syslog-ng/syslog-ng.conf
		options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };\n

		Remediation:
		Edit the /etc/syslog-ng/syslog-ng.conf and set perm option to 0640 or more restrictive:
		options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };\n"

	fi
}

ensure_syslog_ng_is_configured_to_send_logs_to_remote_host () {
                echo -e "\e[92m== 4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host ==\n"
                if [[ "$(grep 'destination logserver' /etc/syslog-ng/syslog-ng.conf 2>/dev/null)" =~ destination.logserver.\{.tcp\(\".+?destination.+\}\; ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Review the /etc/syslog-ng/syslog-ng.conf file and verify that logs are sent to a central host (where logfile.example.com is the name of your central log host):
		destination logserver { tcp(\"logfile.example.com\" port(514)); }; log { source(src); destination(logserver); };\n

		Remediation:
		Edit the /etc/syslog-ng/syslog-ng.conf file and add the following lines (where logfile.example.com is the name of your central log host).
		destination logserver { tcp(\"logfile.example.com\" port(514)); }; log { source(src); destination(logserver); };\n

		Run the following command to restart syslog-ng:
		# pkill -HUP syslog-ng\n"

	fi
}

ensure_remote_syslog_ng_messages_are_only_accepted_on_designated_hosts () {
		echo -e "\e[92m== 4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts (Not Scored) ==\n"
		if [[ "$(grep 'source net' /etc/syslog-ng/syslog-ng.conf 2>/dev/null)" =~ ^source.net\{.tcp\(\).+\;$ && "$(grep 'destination remote' /etc/syslog-ng/syslog-ng.conf 2>/dev/null)" =~ ^destination.remote.+?file.+?log\"\).+?\; && "$(grep 'log {' /etc/syslog-ng/syslog-ng.conf 2>/dev/null)" =~ ^log.\{.source\(net.+?destination\(remote.+?\; ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Review the /etc/syslog-ng/syslog-ng.conf file and verify the following lines are configured appropriately on designated log hosts:
		source net{ tcp(); };
		destination remote { file(\"/var/log/remote/\${FULLHOST}-log\"); };
		log { source(net); destination(remote); };\n

		Remediation:
		On designated log hosts edit the /etc/syslog-ng/syslog-ng.conf file and configure the following lines are appropriately:
		source net{ tcp(); };
		destination remote { file(\"/var/log/remote/\${FULLHOST}-log\"); };
		log { source(net); destination(remote); };\n

		On non designated log hosts edit the /etc/syslog-ng/syslog-ng.conf file and remove or edit any sources that accept network sourced log messages.
		Run the following command to restart syslog-ng:
		# pkill -HUP syslog-ng\n"

	fi
}

ensure_rsyslog_or_syslog_ng_is_installed () {
		echo -e "\e[92m== 4.2.3 Ensure rsyslog or syslog-ng is installed ==\n"
		if [[ "$(dpkg -s rsyslog 2>/dev/null | grep Status)" =~ Status.+ok.installed || "$(dpkg -s syslog-ng 2>/dev/null | grep Status)" =~ Status.+ok.installed ]]
		then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Verify either rsyslog or syslog-ng is installed. Depending on the package management in use one of the following command groups may provide the needed information:
		# dpkg -s rsyslog
	   	# dpkg -s syslog-ng\n

		Remediation:
		Install rsyslog or syslog-ng using one of the following commands:
		# apt-get install rsyslog
		# apt-get install syslog-ng\n"

	fi
}

ensure_permissions_on_all_logfiles_are_configured () {
		echo -e "\e[92m== 4.2.4 Ensure permissions on all logfiles are configured ==\n"
		if [[ "$(find /var/log/ -type f -perm /o+x 2>/dev/null)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Audit:
		Run the following command and verify that other has no permissions on any files and group does not have write or execute permissions on any files:
		# find /var/log -type f -ls\n

		Remediation:
		Run the following command to set permissions on all existing log files:
		# chmod -R g-wx,o-rwx /var/log/*\n

		Notes:
		You may also need to change the configuration for your logging software or services for any logs that had incorrect permissions.\n"

	fi
}

ensure_logrotate_is_configured () {
		echo -e "\e[92m== 4.3 Ensure logrotate is configured (Not Scored) ==\n"
		echo -e "Review the output below from /etc/logrotate.d/* and /etc/logrotate.conf to verify that logs are rotated according to site policy\n"
		echo -e "\e[31m===\n"
		cat /etc/logrotate.conf
		cat /etc/logrotate.d/*
		echo -e "\n===\n\e[0m"
		echo -e "		Audit:
		Review /etc/logrotate.conf and /etc/logrotate.d/* and verify logs are rotated according to site policy.\n

		Remediation:
		Edit /etc/logrotate.conf and /etc/logrotate.d/* to ensure logs are rotated according to site policy.\n"

}

ensure_cron_daemon_is_enabled () {
                echo -e "\e[92m== 5.1.1 Ensure cron daemon is enabled ==\n"
		if [[ "$(systemctl is-enabled crond 2>/dev/null)" = "enabled" || "$(systemctl is-enabled cron 2>/dev/null)" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command to verify cron is enabled:
		# systemctl is-enabled crond
		enabled\n

		Verify result is "enabled".\n

		Remediation:
		Run the following command to enable cron:
		# systemctl enable crond\n"

	fi
}

ensure_permissions_on_etc_crontab_are_configured () {
		echo -e "\e[92m== 5.1.2 Ensure permissions on /etc/crontab are configured ==\n"
		if [[ "$(stat -c %a /etc/crontab 2>/dev/null)" = "600" || "$(stat -c %a /etc/crontab 2>/dev/null)" = "700" && "$(stat -c %U:%G /etc/crontab 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other:
		# stat /etc/crontab
		Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n

		Remediation:
		Run the following commands to set ownership and permissions on /etc/crontab:
		# chown root:root /etc/crontab
		# chmod og-rwx /etc/crontab\n"

	fi
}

ensure_permissions_on_etc_cron_hourly_are_configured () {
		echo -e "\e[92m== 5.1.3 Ensure permissions on /etc/cron.hourly are configured ==\n"
		if [[ "$(stat -c %a /etc/cron.hourly 2>/dev/null)" = "600" || "$(stat -c %a /etc/cron.hourly 2>/dev/null)" = "700" && "$(stat -c %U:%G /etc/cron.hourly 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other:
		# stat /etc/cron.hourly
		Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n

		Remediation:
		Run the following commands to set ownership and permissions on /etc/cron.hourly:
		# chown root:root /etc/cron.hourly
		# chmod og-rwx /etc/cron.hourly\n"

	fi
}

ensure_permissions_on_etc_cron_daily_are_configured () {
                echo -e "\e[92m== 5.1.4 Ensure permissions on /etc/cron.daily are configured ==\n"
		if [[ "$(stat -c %a /etc/cron.daily 2>/dev/null)" = "600" || "$(stat -c %a /etc/cron.daily 2>/dev/null)" = "700" && "$(stat -c %U:%G /etc/cron.daily 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other:
		# stat /etc/cron.daily
		Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n

		Remediation:
		Run the following commands to set ownership and permissions on /etc/cron.daily:
		# chown root:root /etc/cron.daily
		# chmod og-rwx /etc/cron.daily\n"

	fi
}

ensure_permissions_on_etc_cron_weekly_are_configured () {
                echo -e "\e[92m== 5.1.5 Ensure permissions on /etc/cron.weekly are configured ==\n"
		if [[ "$(stat -c %a /etc/cron.weekly 2>/dev/null)" = "600" || "$(stat -c %a /etc/cron.weekly 2>/dev/null)" = "700" && "$(stat -c %U:%G /etc/cron.weekly 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other:
		# stat /etc/cron.weekly
		Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n

		Remediation:
		Run the following commands to set ownership and permissions on /etc/cron.weekly:
		# chown root:root /etc/cron.weekly
		# chmod og-rwx /etc/cron.weekly\n"

	fi
}

ensure_permissions_on_etc_cron_monthly_are_configured () {
                echo -e "\e[92m== 5.1.6 Ensure permissions on /etc/cron.monthly are configured ==\n"
		if [[ "$(stat -c %a /etc/cron.monthly 2>/dev/null)" = "600" || "$(stat -c %a /etc/cron.monthly 2>/dev/null)" = "700" && "$(stat -c %U:%G /etc/cron.monthly 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other:
                # stat /etc/cron.monthly
                Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n

                Remediation:
                Run the following commands to set ownership and permissions on /etc/cron.monthly:
                # chown root:root /etc/cron.monthly
                # chmod og-rwx /etc/cron.monthly\n"

        fi
}

ensure_permissions_on_etc_cron_d_are_configured () {
                echo -e "\e[92m== 5.1.7 Ensure permissions on /etc/cron.d are configured ==\n"
		if [[ "$(stat -c %a /etc/cron.d 2>/dev/null)" = "600" || "$(stat -c %a /etc/cron.d 2>/dev/null)" = "700" && "$(stat -c %U:%G /etc/cron.d 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other:
                # stat /etc/cron.d
                Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n

                Remediation:
                Run the following commands to set ownership and permissions on /etc/cron.d:
                # chown root:root /etc/cron.d
                # chmod og-rwx /etc/cron.d\n"

        fi
}

ensure_at_cron_is_restricted_to_authorized_users () {
                echo -e "\e[92m== 5.1.8 Ensure at/cron is restricted to authorized users  ==\n"
		if [[ ! -f /etc/cron.deny && ! -f /etc/at.deny && "$(stat -c %a /etc/at.allow 2>/dev/null)" = "600" || "$(stat -c %a /etc/at.allow 2>/dev/null)" = "700" && "$(stat -c %U:%G /etc/at.allow 2>/dev/null)" = "root:root" && "$(stat -c %a /etc/cron.allow 2>/dev/null)" = "600" || "$(stat -c %a /etc/cron.allow 2>/dev/null)" = "700" && "$(stat -c %U:%G /etc/cron.allow 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and ensure /etc/cron.deny and /etc/at.deny do not exist:
		# stat /etc/cron.deny
		stat: cannot stat /etc/cron.deny': No such file or directory
		# stat /etc/at.deny
		stat: cannot stat '/etc/at.deny': No such file or directory\n

		Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other for both /etc/cron.allow and /etc/at.allow:
		# stat /etc/cron.allow
		Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)
		# stat /etc/at.allow
		Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)

		Remediation:
		Run the following commands to remove /etc/cron.deny and /etc/at.deny and create and set permissions and ownership for /etc/cron.allow and /etc/at.allow:
		# rm /etc/cron.deny
		# rm /etc/at.deny
		# touch /etc/cron.allow
		# touch /etc/at.allow
		# chmod og-rwx /etc/cron.allow
		# chmod og-rwx /etc/at.allow
		# chown root:root /etc/cron.allow
		# chown root:root /etc/at.allow\n"

	fi
}

ensure_permissions_on_etc_ssh_sshd_config_are_configured () {
                echo -e "\e[92m== 5.2 Ensure permissions on /etc/ssh/sshd_config are configured ==\n"
                if [[ "$(stat -c %a /etc/ssh/sshd_config 2>/dev/null)" = "600" && "$(stat -c %U:%G /etc/ssh/sshd_config 2>/dev/null)" = "root:root" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify Uid and Gid are both 0/root and Access does not grant permissions to group or other:
		# stat /etc/ssh/sshd_config
		Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n

		Remediation:
		Run the following commands to set ownership and permissions on /etc/ssh/sshd_config:
		# chown root:root /etc/ssh/sshd_config
		# chmod og-rwx /etc/ssh/sshd_config\n"

	fi
}

ensure_ssh_protocol_is_set_to_2 () {
                echo -e "\e[92m== 5.2.2 Ensure SSH Protocol is set to 2 ==\n"
		if [[ "$(grep "^Protocol" /etc/ssh/sshd_config 2>/dev/null)" = "Protocol 2" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output matches:
		# grep \"^Protocol\" /etc/ssh/sshd_config
		Protocol 2\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		Protocol 2\n"

	fi
}

ensure_ssh_loglevel_is_set_to_info () {
		echo -e "\e[92m== 5.2.3 Ensure SSH LogLevel is set to INFO ==\n"
		if [[ "$(grep "^LogLevel" /etc/ssh/sshd_config 2>/dev/null)" = "LogLevel INFO" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output matches:
		# grep "^LogLevel" /etc/ssh/sshd_config
		LogLevel INFO\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		LogLevel INFO\n"

	fi
}

ensure_ssh_x11_forwarding_is_disabled () {
		echo -e "\e[92m== 5.2.4 Ensure SSH X11 forwarding is disabled ==\n"
		if [[ "$(grep ^X11Forwarding /etc/ssh/sshd_config 2>/dev/null)" = "X11Forwarding no" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output matches:
		# grep "^X11Forwarding" /etc/ssh/sshd_config
		X11Forwarding no\n

		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		X11Forwarding no\n"

	fi
}

ensure_ssh_MaxAuthTries_is_set_to_4_or_less () {
		echo -e "\e[92m== 5.2.5 Ensure SSH MaxAuthTries is set to 4 or less  ==\n"
		if [[ "$(grep ^MaxAuthTries /etc/ssh/sshd_config 2>/dev/null)" =~ MaxAuthTries.[1,2,3,4] ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output MaxAuthTries is 4 or less:
		# grep \"^MaxAuthTries\" /etc/ssh/sshd_config
		MaxAuthTries 4\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		MaxAuthTries 4\n"

	fi
}

ensure_ssh_IgnoreRhosts_is_enabled () {
		echo -e "\e[92m== 5.2.6 Ensure SSH IgnoreRhosts is enabled ==\n"
		if [[ "$(grep ^IgnoreRhosts /etc/ssh/sshd_config 2>/dev/null)" = "IgnoreRhosts yes" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output matches:
		# grep \"^IgnoreRhosts\" /etc/ssh/sshd_config
		IgnoreRhosts yes\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		IgnoreRhosts yes\n"

	fi
}

ensure_ssh_hostbasedAuthentication_is_disabled () {
		echo -e "\e[92m== 5.2.7 Ensure SSH HostbasedAuthentication is disabled ==\n"
		if [[ "$(grep "^HostbasedAuthentication" /etc/ssh/sshd_config 2>/dev/null)" = "HostbasedAuthentication no" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output matches:
		# grep "^HostbasedAuthentication" /etc/ssh/sshd_config
		HostbasedAuthentication no\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		HostbasedAuthentication no\n"

	fi
}

ensure_ssh_root_login_is_disabled () {
                echo -e "\e[92m== 5.2.8 Ensure SSH root login is disabled ==\n"
		if [[ "$(grep ^PermitRootLogin /etc/ssh/sshd_config 2>/dev/null)" = "PermitRootLogin no" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output matches:
		# grep \"^PermitRootLogin\" /etc/ssh/sshd_config
		PermitRootLogin no\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		PermitRootLogin no\n"

	fi
}

ensure_ssh_PermitEmptyPasswords_is_disabled () {
		echo -e "\e[92m== 5.2.9 Ensure SSH PermitEmptyPasswords is disabled ==\n"
		if [[ "$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config 2>/dev/null)" = "PermitEmptyPasswords no" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output matches:
		# grep \"^PermitEmptyPasswords\" /etc/ssh/sshd_config
		PermitEmptyPasswords no\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		PermitEmptyPasswords no\n"

	fi

}

ensure_ssh_PermitUserEnvironment_is_disabled () {
		echo -e "\e[92m== 5.2.10 Ensure SSH PermitUserEnvironment is disabled ==\n"
		if [[ "$(grep PermitUserEnvironment /etc/ssh/sshd_config 2>/dev/null)" = "PermitUserEnvironment no" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output matches:
		# grep PermitUserEnvironment /etc/ssh/sshd_config
		PermitUserEnvironment no\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		PermitUserEnvironment no\n"

	fi
}

ensure_only_approved_mac_algorithms_are_used () {
		echo -e "\e[92m== 5.2.11 Ensure only approved MAC algorithms are used ==\n"
		if [[ "$(grep MACs /etc/ssh/sshd_config 2>/dev/null)" = "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" || "$(grep MACs /etc/ssh/sshd_config 2>/dev/null)" = "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output does not contain any unlisted MAC algorithms:
		# grep \"MACs\" /etc/ssh/sshd_config
		MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\n"

	fi
}

ensure_ssh_idle_timeout_interval_is_configured () {
		echo -e "\e[92m== 5.2.12 Ensure SSH Idle Timeout Interval is configured ==\n"
		if [[ "$(grep ^ClientAliveInterval /etc/ssh/sshd_config 2>/dev/null | cut -d ' ' -f2)" -lt 301 && "$(grep ^ClientAliveCountMax /etc/ssh/sshd_config 2>/dev/null | cut -d ' ' -f2)" -lt 4 && "$(grep ^ClientAliveInterval /etc/ssh/sshd_config 2>/dev/null | cut -d ' ' -f2 )" -gt 0 ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify ClientAliveInterval is 300 or less and ClientAliveCountMax is 3 or less:
		# grep \"^ClientAliveInterval\" /etc/ssh/sshd_config
		ClientAliveInterval 300
		# grep \"^ClientAliveCountMax\" /etc/ssh/sshd_config
		ClientAliveCountMax 0\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameters as follows:
		ClientAliveInterval 300
		ClientAliveCountMax 0\n"

	fi
}

ensure_ssh_LoginGraceTime_is_set_to_one_minute_or_less () {
		echo -e "\e[92m== 5.2.13 Ensure SSH LoginGraceTime is set to one minute or less ==\n"
		if [[ "$(grep ^LoginGraceTime /etc/ssh/sshd_config 2>/dev/null | cut -d ' ' -f2)" -lt 61 ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output LoginGraceTime is 60 or less:
		# grep \"^LoginGraceTime\" /etc/ssh/sshd_config
		LoginGraceTime 60\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		LoginGraceTime 60\n"

	fi
}

ensure_ssh_access_is_limited () {
		echo -e "\e[92m== 5.2.14 Ensure SSH access is limited ==\n"
		if [[ "$(grep ^AllowUsers /etc/ssh/sshd_config 2>/dev/null)" =~ AllowUsers.+$ || "$(grep ^AllowGroups /etc/ssh/sshd_config 2>/dev/null)" =~ AllowGroups.+$ || "$(grep ^DenyUsers /etc/ssh/sshd_config 2>/dev/null)" =~ DenyUsers.+$ || "$(grep ^DenyGroups /etc/ssh/sshd_config 2>/dev/null)" =~ DenyGroups.+$ ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify that output matches for at least one:
		# grep \"^AllowUsers\" /etc/ssh/sshd_config AllowUsers <userlist>
		# grep \"^AllowGroups\" /etc/ssh/sshd_config AllowGroups <grouplist>
		# grep \"^DenyUsers\" /etc/ssh/sshd_config DenyUsers <userlist>
		# grep \"^DenyGroups\" /etc/ssh/sshd_config DenyGroups <grouplist>\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set one or more of the parameter as follows:
		AllowUsers <userlist>
		AllowGroups <grouplist>
		DenyUsers <userlist>
		DenyGroups <grouplist>\n"

	fi
}

ensure_ssh_warning_banner_is_configured () {
		echo -e "\e[92m== 5.2.15 Ensure SSH warning banner is configured ==\n"
		if [[ "$(grep ^Banner /etc/ssh/sshd_config 2>/dev/null)" = "Banner /etc/issue.net" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that output matches:
		# grep \"^Banner\" /etc/ssh/sshd_config
		Banner /etc/issue.net\n

		Remediation:
		Edit the /etc/ssh/sshd_config file to set the parameter as follows:
		Banner /etc/issue.net\n"

	fi
}

ensure_password_creation_requirements_are_configured () {
		echo -e "\e[92m== 5.3.1 Ensure password creation requirements are configured ==\n"
		if [[ "$(grep pam_pwquality.so /etc/pam.d/common-password 2>/dev/null)" = "password requisite pam_pwquality.so try_first_pass retry=3" && "$(grep ^minlen /etc/security/pwquality.conf 2>/dev/null | cut -d \= -f2)" -gt 13 && "$(grep ^dcredit /etc/security/pwquality.conf 2>/dev/null | cut -d \= -f2)" -gt -2 && "$(grep ^lcredit /etc/security/pwquality.conf 2>/dev/null | cut -d \= -f2)" -gt -2 && "$(grep ^ocredit /etc/security/pwquality.conf 2>/dev/null | cut -d \= -f2)" -gt -2 && "$(grep ^ucredit /etc/security/pwquality.conf 2>/dev/null | cut -d \= -f2)" -gt -2 ]]
		then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify all password requirements are as listed or stricter:
		# grep pam_pwquality.so /etc/pam.d/common-password
		password requisite pam_pwquality.so try_first_pass retry=3
		# grep ^minlen /etc/security/pwquality.conf
		minlen=14
		# grep ^dcredit /etc/security/pwquality.conf
		dcredit=-1
		# grep ^lcredit /etc/security/pwquality.conf
		lcredit=-1
		# grep ^ocredit /etc/security/pwquality.conf
		ocredit=-1
		# grep ^ucredit /etc/security/pwquality.conf
		ucredit=-1\n


		Remediation:
		Run the following command to install the pam_pwquality module:
		apt-get install libpam-pwquality
		Edit the /etc/pam.d/common-passwd file to include the appropriate options for pam_pwquality.so and to conform to site policy:
		password requisite pam_pwquality.so try_first_pass retry=3
		Edit /etc/security/pwquality.conf to add or update the following settings to conform to site policy:
		minlen=14
		dcredit=-1
		ucredit=-1
		ocredit=-1
		lcredit=-1\n

		Notes:
		Additional module options may be set, recommendation only covers those listed here. \n"
	fi
}

ensure_lockout_for_failed_password_attempts_is_configured () {
		echo -e "\e[92m== 5.3.2 Ensure lockout for failed password attempts is configured (Not Scored) ==\n"
		if [[ "$(grep pam_tally2 /etc/pam.d/common-auth 2>/dev/null)" = "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Perform the following to determine the current settings for user lockout.
		# grep \"pam_tally2\" /etc/pam.d/common-auth
		auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900\n

		Remediation:
		Edit the /etc/pam.d/common-auth file and add the auth line below:
		auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900\n

		Note: If a user has been locked out because they have reached the maximum consecutive failure count defined by deny= in the pam_tally2.so module, the user can be unlocked by issuing the command /sbin/pam_tally2 -u <username> --reset. This command sets the failed count to 0, effectively unlocking the user.\n"

	fi
}

ensure_password_reuse_is_limited () {
		echo -e "\e[92m== 5.3.3 Ensure password reuse is limited ==\n"
		if [[ "$(egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/common-password 2>/dev/null | cut -d \= -f2)" -gt 4 ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and ensure the remember option is '5' or more and included in all results:
		# egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/common-password
		password sufficient pam_unix.so remember=5\n

		Remediation:
		Edit the /etc/pam.d/common-password file to include the remember option and conform to site policy as shown:
		password sufficient pam_unix.so remember=5\n

		Notes:
		Additional module options may be set, recommendation only covers those listed here.\n"

	fi
}

ensure_password_hashing_algorithm_is_sha_512 () {
		echo -e "\e[92m== 5.3.4 Ensure password hashing algorithm is SHA-512 ==\n"
		if [[ "$(egrep '^password\s+\S+\s+pam_unix.so' /etc/pam.d/common-password 2>/dev/null)" =~ password.+?sha512+$ ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and ensure the sha512 option is included in all results:
		# egrep '^password\s+\S+\s+pam_unix.so' /etc/pam.d/common-password
		password sufficient pam_unix.so sha512\n

		Audit:
		Run the following commands and ensure the sha512 option is included in all results:
		# egrep '^password\\s+\\S+\\s+pam_unix.so' /etc/pam.d/common-password
		password sufficient pam_unix.so sha512\n

		Remediation:
		Edit the /etc/pam.d/common-password file to include the sha512 option for pam_unix.so as shown:
		password [success=1 default=ignore] pam_unix.so sha512\n

		Notes:
		Additional module options may be set, recommendation only covers those listed here.
		If it is determined that the password algorithm being used is not SHA-512, once it is changed, it is recommended that all user ID's be immediately expired and forced to change their passwords on next login. To accomplish that, the following commands can be used. Any system accounts that need to be expired should be carefully done separately by the system administrator to prevent any potential problems.
		# cat /etc/passwd | awk -F: '( \$3 >= 1000 && \$1 != \"nfsnobody\" ) { print \$1 }' | xargs
		-n 1 chage -d 0\n"

	fi
}

ensure_password_expiration_is_90_days_or_less () {
		echo -e "\e[92m== 5.4.1.1 Ensure password expiration is 90 days or less ==\n"
		if [[ "$(grep -oP "(?<=^PASS_MAX_DAYS\s).+$" /etc/login.defs 2>/dev/null)" -lt 91 ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify PASS_MAX_DAYS is 90 or less:
		grep PASS_MAX_DAYS /etc/login.defs
		PASS_MAX_DAYS 90\n

		Verify all users with a password have their maximum days between password change set
		to 90 or less:
		# egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
		<list of users>
		# chage --list <user>
		Maximum number of days between password change : 90\n

		Remediation:
		Set the PASS_MAX_DAYS parameter to 90 in /etc/login.defs:
		PASS_MAX_DAYS 90\n

		Modify user parameters for all users with a password set to match:
		# chage --maxdays 90 <user>\n

		Notes:
		You can also check this setting in /etc/shadow directly. The 5th field should be 90 or less for all users with a password.\n

		Also, ensure that the 'Maximum number of days between password change' is set to 90 or less for these users:\n"

		for i in $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1)
		do
			number=$(chage --list $i | grep 'Maximum number' | cut -d \: -f2)
		if [[ $number -lt 91 ]]
		then echo ''
		else
			echo "		$i : $number"
		fi

		done

	fi
}

ensure_minimum_days_between_password_change_is_7_days_or_more () {
		echo -e "\e[92m== 5.4.1.2 Ensure minimum days between password changes is 7 or more ==\n"
		if [[ "$(grep -oP "(?<=^PASS_MIN_DAYS\s).+$" /etc/login.defs 2>/dev/null)" -gt 6 ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify PASS_MIN_DAYS is 7 or more:
		# grep PASS_MIN_DAYS /etc/login.defs
		PASS_MIN_DAYS 7\n

		Verify all users with a password have their minimum days between password change set to
		7 or more:
		# egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
		<list of users>
		# chage --list <user>
		Minimum number of days between password change : 7\n

		Remediation:
		Set the PASS_MIN_DAYS parameter to 7 in /etc/login.defs: PASS_MIN_DAYS 7
		Modify user parameters for all users with a password set to match:
		# chage --mindays 7 <user>\n

		Notes:
		You can also check this setting in /etc/shadow directly. The 5th field should be 7 or more for all users with a password.\n"

	fi

        echo -e "The PASS_MIN_DAYS parameter needs to be set for these users:\n"

        for i in $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1)
        do
                number=$(chage --list $i | grep 'Minimum number of days' | cut -d : -f2)
                if [[ $number -gt 6 ]]
                then echo ''
                else
                        echo "          $i : $number"

                fi
                done
	echo -e "\n"

}

ensure_password_expiration_warning_is_7_days_or_more () {
		echo -e "\e[92m== 5.4.1.3 Ensure password expiration warning days is 7 or more ==\n"
		if [[ "$(grep -oP "(?<=^PASS_WARN_AGE\s).+$" /etc/login.defs 2>/dev/null)" -gt 6 ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify PASS_WARN_AGE is 7 or more:
		# grep PASS_WARN_AGE /etc/login.defs
		PASS_WARN_AGE 7

		Verify all users with a password have their number of days of warning before password
		expires set to 7 or more:

		# egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
		<list of users>
		# chage --list <user>
		Number of days of warning before password expires : 7

		Remediation:
		Set the PASS_WARN_AGE parameter to 7 in /etc/login.defs:
		PASS_WARN_AGE 7

		Modify user parameters for all users with a password set to match:
		# chage --warndays 7 <user>

		Notes:
		You can also check this setting in /etc/shadow directly. The 6th field should be 7 or more for all users with a password.\n"

	fi

	echo -e "The PASS_WARN_AGE parameter needs to be set for these users:\n"

	for i in $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1)
	do
		number=$(chage --list $i | grep 'warning before password expires' | cut -d : -f2)
		if [[ $number -gt 6 ]]
		then echo ''
		else
			echo "		$i : $number"

		fi

		done
	echo -e "\n"

}

ensure_inactive_password_lock_is_30_days_or_less () {
		echo -e "\e[92m== 5.4.1.4 Ensure inactive password lock is 30 days or less ==\n"
		if [[ "$(useradd -D | grep INACTIVE | cut -d \= -f2)" -lt 31 ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify INACTIVE is 30 or less:
		useradd -D | grep INACTIVE
		INACTIVE=35\n

		Verify all users with a password have Password inactive no more than 30 days after
		password expires:
		# egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
		<list of users>
		# chage --list <user>
		Password inactive\n

		Remediation:
		Run the following command to set the default password inactivity period to 30 days:
		# useradd -D -f 30\n

		Modify user parameters for all users with a password set to match:
		# chage --inactive 30 <user>\n

		Notes:
		You can also check this setting in /etc/shadow directly. The 7th field should be 30 or less for all users with a password.\n"

	fi

	echo -e "The following users need to have their password lock set to 30 days or less:\n"
		for i in $(egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1)
		do
			number=$(chage --list $i | grep 'Minimum number of days' | cut -d : -f2)
			if [[ $number -lt 31 ]]
			then echo ''
			else
				echo -e "		$i : $number"
			fi
		done

		echo -e "\n"

}

ensure_system_accounts_are_non_login () {
		echo -e "\e[92m== 5.4.2 Ensure system accounts are non-login ==\n"
		if [[ "$(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}')" = "" ]]
		then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following script and verify no results are returned:
		egrep -v \"^\+\" /etc/passwd | awk -F: '(\$1!=\"root\" && \$1!=\"sync\" && \$1!=\"shutdown\" && \$1!=\"halt\" && \$3<1000 && \$7!=\"/usr/sbin/nologin\" && \$7!=\"/bin/false\") {print}\'

		Remediation:
		Set the shell for any accounts returned by the audit script to /usr/sbin/nologin:
		# usermod -s /usr/sbin/nologin <user>
		The following script will automatically set all user shells required to /usr/sbin/nologin and lock the sync, shutdown, and halt users:

		#!/bin/bash
		for user in \`awk -F: '(\$3 < 1000) {print \$1 }' /etc/passwd\`; do
		  if [ \$user != \"root\" ]; then
		    usermod -L \$user
		    if [ \$user != "sync" ] && [ \$user != "shutdown" ] && [ \$user != \"halt\" ]; then
      			usermod -s /usr/sbin/nologin \$user
    		fi
	fi
done\n"

fi
}

ensure_default_group_for_root_account_is_gid_0 () {
		echo -e "\e[92m== 5.4.3 Ensure default group for the root account is GID 0 ==\n"
		if [[ "$(grep ^root: /etc/passwd | cut -f4 -d:)" = "0" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify the result is 0:
		# grep \"^root:\" /etc/passwd | cut -f4 -d:
		0\n

		Remediation:
		Run the following command to set the root user default group to GID 0:
		# usermod -g 0 root\n"

	fi
}

ensure_default_user_umask_is_027_or_more_restrictive () {
		echo -e "\e[92m== 5.4.4 Ensure default user umask is 027 or more restrictive ==\n"
		if [[ "$(grep -oP "(?<=^umask\s).+$" /etc/bash.bashrc 2>/dev/null)" = "027" && "$(grep -oP "(?<=^umask\s).+$" /etc/profile 2>/dev/null)" = "027" ]]
		                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify all umask lines returned are 027 or more restrictive.
		# grep \"^umask\" /etc/bash.bashrc
		umask 027
		# grep \"^umask\" /etc/profile
		umask 027\n

		Remediation:
		Edit the /etc/bash.bashrc and /etc/profile files (and the appropriate files for any other shell supported on your system) and add or edit any umask parameters as follows:
		umask 027\n

		Notes:
		The audit and remediation in this recommendation apply to bash and shell. If other shells are supported on the system, it is recommended that their configuration files also are checked.
		Other methods of setting a default user umask exist however the shell configuration files are the last run and will override other settings if they exist therefore our recommendation is to configure in the shell configuration files. If other methods are in use in your environment they should be audited and the shell configs should be verified to not override.\n"

	fi
}

ensure_root_login_is_restricted_to_system_console () {
		echo -e "\e[92m== 5.5 Ensure root login is restricted to system console (Not Scored) ==\n"
		echo -e "\e[0mVerify that the terminals listed below from the /etc/securetty terminal are in physically secure locations.  Remove any that are not.\n"
		echo -e "\e[31m=== cat /etc/securetty ===\n"
		cat /etc/securetty
		echo -e "\n======\n"
		echo -e "\e[0m		Audit:
		Audit:
		Since the system console has special properties to handle emergency situations, it is important to ensure that the console is in a physically secure location and that unauthorized consoles have not been defined.
		# cat /etc/securetty

		Remediation:
		Remove entries for any consoles that are not in a physically secure location.\n"


}

ensure_access_to_the_su_command_is_restricted () {
		echo -e "\e[92m== 5.6 Ensure access to the su command is restricted ==\n"
		if [[ "$(grep pam_wheel.so /etc/pam.d/su)" = "auth required pam_wheel.so use_uid" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify output includes matching line:
		# grep pam_wheel.so /etc/pam.d/su
		auth required pam_wheel.so use_uid\n

		Run the following command and verify users in wheel group match site policy:
		# grep wheel /etc/group
		wheel:x:10:root,<user list>\n

		Remediation:
		Add the following line to the /etc/pam.d/su file: auth required pam_wheel.so use_uid
		Create a comma separated list of users in the wheel statement in the /etc/group file:
		wheel:x:10:root,<user list>\n"

	fi

	echo -e "Verify the users in the wheel group below match site policy:\n"
	echo -e "=== grep wheel /etc/group ===\n"
	grep wheel /etc/group
	echo -e "\n======\n"

}

audit_system_file_permissions () {
		echo -e "\e[92m== 6.1.1 Audit system file permissions ==\n"
		echo -e "\e[0mVerify that the output below from the 'dpkg --verify' on all packages below is correct.  This could take a long time to run:\n"
		echo -e "\e[31m=== dpkg --verify <package> (on all packages on the system) ===\n"
		for i in `apt list --installed 2>/dev/null | cut -d / -f1` ; do dpkg --verify $i 2>/dev/null  ; done ;
		echo -e "======\e[0m \n"

		echo -e "	Audit:
		Run the following command to review all installed packages. Note that this may be very time consuming and may be best scheduled via the cron utility. It is recommended that the output of this command be redirected to a file that can be reviewed later.
		# dpkg --verify > <filename>\n

		Remediation:
		Correct any discrepancies found and rerun the audit until output is clean or risk is mitigated or accepted.\n

		Notes:
		Since packages and important files may change with new updates and releases, it is recommended to verify everything, not just a finite list of files. This can be a time consuming task and results may depend on site policy therefore it is not a scorable benchmark item, but is provided for those interested in additional security measures.
		Some of the recommendations of this benchmark alter the state of files audited by this recommendation. The audit command will alert for all changes to a file permissions even if the new state is more secure than the default.\n"

}

ensure_permissions_on_etc_passwd_are_configured () {
		echo -e "\e[92m== 6.1.2 Ensure permissions on /etc/passwd are configured ==\n"
                if [[ "$(stat -c %a /etc/passwd 2>/dev/null)" = "644" && "$(stat -c %U:%G /etc/passwd 2>/dev/null)" = "root:root" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify Uid and Gid are both 0/root and Access is 644:
		# stat /etc/passwd
		Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)\n

		Remediation:
		Run the following command to set permissions on /etc/passwd:
		# chown root:root /etc/passwd
		# chmod 644 /etc/passwd\n"

	fi
}

ensure_permissions_on_etc_shadow_are_configured () {
                echo -e "\e[92m== 6.1.3 Ensure permissions on /etc/shadow are configured ==\n"
                if [[ "$(stat -c %a /etc/shadow 2>/dev/null)" = "640" && "$(stat -c %U:%G /etc/shadow 2>/dev/null)" = "root:shadow" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify Uid and Gid are both 0/root and Access is 644:
		# stat /etc/shadow
		Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)

		Remediation:
                Run the following command to set permissions on /etc/shadow:
		# chown root:shadow /etc/shadow
		# chmod o-rwx,g-wx /etc/shadow\n"

        fi
}

ensure_permissions_on_etc_group_are_configured () {
                echo -e "\e[92m== 6.1.4 Ensure permissions on /etc/group are configured ==\n"
                if [[ "$(stat -c %a /etc/group 2>/dev/null)" = "644" && "$(stat -c %U:%G /etc/group 2>/dev/null)" = "root:root" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify Uid and Gid are both 0/root and Access is 644:
                # stat /etc/group
                Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)\n

                Remediation:
                Run the following command to set permissions on /etc/group:
                # chown root:root /etc/group
                # chmod 644 /etc/group\n"

        fi
}

ensure_permissions_on_etc_gshadow_are_configured () {
		echo -e "\e[92m== 6.1.5 Ensure permissions on /etc/gshadow are configured ==\n"
                if [[ "$(stat -c %a /etc/gshadow 2>/dev/null)" = "640" && "$(stat -c %U:%G /etc/gshadow 2>/dev/null)" = "root:shadow" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify verify Uid is 0/root, Gid is <gid>/shadow, and Access is 640 or more restrictive:
		# stat /etc/gshadow
		Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (   42/  shadow)\n

		Remediation:
		Run the following commands to set permissions on /etc/gshadow:
		# chown root:shadow /etc/gshadow
		# chmod o-rwx,g-rw /etc/gshadow\n"

	fi
}

ensure_permissions_on_etc_passwd__are_configured () {
		echo -e "\e[92m== 6.1.6 Ensure permissions on /etc/passwd- are configured ==\n"
		if [[ "$(stat -c %a /etc/passwd- 2>/dev/null)" = "600" && "$(stat -c %U:%G /etc/passwd- 2>/dev/null)" = "root:root" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify Uid and Gid are both 0/root and Access is 600 or more restrictive:
		# stat /etc/passwd-
		Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n

		Remediation:
		Run the following command to set permissions on /etc/passwd-:
		# chown root:root /etc/passwd-
		# chmod 600 /etc/passwd-\n"

	fi
}


ensure_permissions_on_etc_shadow__are_configured () {
                echo -e "\e[92m== 6.1.7 Ensure permissions on /etc/shadow- are configured ==\n"
                if [[ "$(stat -c %a /etc/shadow- 2>/dev/null)" = "600" && "$(stat -c %U:%G /etc/shadow- 2>/dev/null)" = "root:root" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify Uid and Gid are both 0/root and Access is 600 or more restrictive:
                # stat /etc/shadow-
                Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n

                Remediation:
                Run the following command to set permissions on /etc/shadow-:
                # chown root:root /etc/shadow-
                # chmod 600 /etc/shadow-\n"

        fi
}

ensure_permissions_on_etc_group__are_configured () {
                echo -e "\e[92m== 6.1.8 Ensure permissions on /etc/group- are configured ==\n"
                if [[ "$(stat -c %a /etc/group- 2>/dev/null)" = "600" && "$(stat -c %U:%G /etc/group- 2>/dev/null)" = "root:root" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify Uid and Gid are both 0/root and Access is 600 or more restrictive:
                # stat /etc/group-
                Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n

                Remediation:
                Run the following command to set permissions on /etc/group-:
                # chown root:root /etc/group-
                # chmod 600 /etc/group-\n"

        fi
}

ensure_permissions_on_etc_gshadow__are_configured () {
                echo -e "\e[92m== 6.1.9 Ensure permissions on /etc/gshadow- are configured ==\n"
                if [[ "$(stat -c %a /etc/gshadow- 2>/dev/null)" = "600" && "$(stat -c %U:%G /etc/gshadow- 2>/dev/null)" = "root:root" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify Uid and Gid are both 0/root and Access is 600 or more restrictive:
                # stat /etc/gshadow-
                Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)\n

                Remediation:
                Run the following command to set permissions on /etc/gshadow-:
                # chown root:root /etc/gshadow-
                # chmod 600 /etc/gshadow-\n"

        fi
}

ensure_no_world_writable_files_exist () {
		echo -e "\e[92m== 6.1.10 Ensure no world writable files exist ==\n"
		if [[ "$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null)" = "" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify no files are returned:
		# df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002\n

		The command above only searches local filesystems, there may still be compromised items on network mounted partitions. Additionally the --local option to df is not universal to all versions, it can be omitted to search all filesystems on a system including network mounted filesystems or the following command can be run manually for each partition:
		# find <partition> -xdev -type f -perm -0002\n

		Remediation:
		Removing write access for the "other" category (chmod o-w <filename>) is advisable, but always consult relevant vendor documentation to avoid breaking any application dependencies on a given file.\n"

	fi
}

ensure_no_unowned_files_or_directories_exist () {
		echo -e "\e[92m== 6.1.11 Ensure no unowned files or directories exist ==\n"
		if [[ "$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null)" = "" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify no files are returned:
		# df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -nouser\n

		The command above only searches local filesystems, there may still be compromised items on network mounted partitions. Additionally the --local option to df is not universal to all versions, it can be omitted to search all filesystems on a system including network mounted filesystems or the following command can be run manually for each partition:
		# find <partition> -xdev -nouser\n

		Remediation:
		Locate files that are owned by users or groups not listed in the system configuration files, and reset the ownership of these files to some active user on the system as appropriate.\n"

	fi
}

ensure_no_ungrouped_files_or_directories_exist () {
		echo -e "\e[92m== 6.1.12 Ensure no ungrouped files or directories exist ==\n"
		if [[ "$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null)" = "" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify no files are returned:
		# df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -nogroup\n

		The command above only searches local filesystems, there may still be compromised items on network mounted partitions. Additionally the --local option to df is not universal to all versions, it can be omitted to search all filesystems on a system including network mounted filesystems or the following command can be run manually for each partition:
		# find <partition> -xdev -nogroup\n

		Remediation:
		Locate files that are owned by users or groups not listed in the system configuration files, and reset the ownership of these files to some active user on the system as appropriate.\n"

	fi
}

audit_suid_executables () {
		echo -e "\e[92m== 6.1.13 Audit SUID executables (Not Scored) ==\n"
		echo -e "\e[0mVerify that only the files that should have SUID permissions are listed below:\n"
		echo -e "\e[31m=== df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 ===\n"
		df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 2>/dev/null
		echo -e "\n======\e[0m\n"
		echo -e "		Audit:
		Run the following command to list SUID files:
		# df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000\n

		The command above only searches local filesystems, there may still be compromised items on network mounted partitions. Additionally the --local option to df is not universal to all versions, it can be omitted to search all filesystems on a system including network mounted filesystems or the following command can be run manually for each partition:
		# find <partition> -xdev -type f -perm -4000

		Remediation:
		Ensure that no rogue SUID programs have been introduced into the system. Review the files returned by the action in the Audit section and confirm the integrity of these binaries.\n"


}

audit_sgid_executables () {
		echo -e "\e[92m== 6.1.14 Audit SGID executables ==\n"
		echo -e "\e[0mVerify that only the files that should have SGID permissions are listed below:\n"
		echo -e "\e[31m=== df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 ===\n"
		df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 2>/dev/null
                echo -e "\n======\e[0m\n"
                echo -e "               Audit:
		Run the following command to list SGID files:
		# df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000\n

		The command above only searches local filesystems, there may still be compromised items on network mounted partitions. Additionally the --local option to df is not universal to all versions, it can be omitted to search all filesystems on a system including network mounted filesystems or the following command can be run manually for each partition:
		# find <partition> -xdev -type f -perm -2000\n

		Remediation:
		Ensure that no rogue SGID programs have been introduced into the system. Review the files returned by the action in the Audit section and confirm the integrity of these binaries.\n"

}

ensure_password_fields_are_not_empty () {
		echo -e "\e[92m== 6.2.1 Ensure password fields are not empty ==\n"
		if [[ "$(cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}')" = "" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n               The following users do not have a password:\n"
		cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'
		echo -e "\n"
		echo -e "		Audit:
		Run the following command and verify that no output is returned:
		# cat /etc/shadow | awk -F: '(\$2 == \"\" ) { print \$1 \" does not have a password \"}'\n

		Remediation:
		If any accounts in the /etc/shadow file do not have a password, run the following command to lock the account until it can be determined why it does not have a password:
		# passwd -l <username>\n

		Also, check to see if the account is logged in and investigate what it is being used for to determine if it needs to be forced off.\n"

	fi
}

ensure_no_legacy_+_entries_exist_in_etc_passwd () {
		echo -e "\e[92m== 6.2.2 Ensure no legacy \"+\" entries exist in /etc/passwd ==\n"
		if [[ "$(grep '^+:' /etc/passwd 2>/dev/null)" = "" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that no output is returned:
		# grep '^+:' /etc/passwd\n

		Remediation:
		Remove any legacy '+' entries from /etc/passwd if they exist.\n"

	fi
}

ensure_no_legacy_+_entries_exist_in_etc_shadow () {
                echo -e "\e[92m== 6.2.3 Ensure no legacy \"+\" entries exist in /etc/shadow ==\n"
                if [[ "$(grep '^+:' /etc/shadow 2>/dev/null)" = "" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify that no output is returned:
                # grep '^+:' /etc/shadow\n

                Remediation:
                Remove any legacy '+' entries from /etc/shadow if they exist.\n"

        fi
}

ensure_no_legacy_+_entries_exist_in_etc_group () {
                echo -e "\e[92m== 6.2.4 Ensure no legacy \"+\" entries exist in /etc/group ==\n"
                if [[ "$(grep '^+:' /etc/group 2>/dev/null)" = "" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
                Run the following command and verify that no output is returned:
                # grep '^+:' /etc/group\n

                Remediation:
                Remove any legacy '+' entries from /etc/group if they exist.\n"

        fi
}

ensure_root_is_the_only_uid_0_account () {
		echo -e "\e[92m== 6.2.5 Ensure root is the only UID 0 account ==\n"
		if [[ "$(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }')" = "root" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following command and verify that only \"root\" is returned:
		# cat /etc/passwd | awk -F: '(\$3 == 0) { print \$1 }'
		root\n

		Remediation:
		Remove any users other than root with UID 0 or assign them a new UID if appropriate.\n"

	fi
}

ensure_root_path_integrity () {
	echo -e "\e[92m== 6.2.6 Ensure root PATH Integrity ==\n"
output=$(if [ "`echo $PATH | grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)"
fi
if [ "`echo $PATH | grep :$`"  != "" ]; then
  echo "Trailing : in PATH"
fi
p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
  if [ "$1" = "." ]; then
    echo "PATH contains ."
    shift
    continue
  fi
  if [ -d $1 ]; then
    dirperm=`ls -ldH $1 | cut -f1 -d" "`
    if [ `echo $dirperm | cut -c6 ` != "-" ]; then
      echo "Group Write permission set on directory $1"
    fi
    if [ `echo $dirperm | cut -c9 ` != "-" ]; then
      echo "Other Write permission set on directory $1"
    fi
    dirown=`ls -ldH $1 | awk '{print $3}'`
    if [ "$dirown" != "root" ] ; then
      echo $1 is not owned by root
    fi
  else
    echo $1 is not a directory

	fi
	shift
done)


		if [[ $output = "" ]]

                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \nReview the following issues that were found with the path integrity:\n"
		echo $output
		echo -e "\n"

		echo -e "		Audit:
		Run the following script and verify no results are returned:
#!/bin/bash
if [ \"\`echo $PATH | grep :: \`\" != \"\" ]; then
    echo \"Empty Directory in PATH (::)\"
fi
if [ \"\`echo $PATH | grep :$\`\"  != \"\" ]; then
  echo \"Trailing : in PATH\"
fi
p=\`echo \$PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'\`
set -- $p
while [ \"\$1\" != \"\" ]; do
  if [ \"\$1\" = \".\" ]; then
    echo \"PATH contains .\"
    shift
    continue
  fi
  if [ -d \$1 ]; then
    dirperm=\`ls -ldH \$1 | cut -f1 -d\" \"\`
    if [ \`echo \$dirperm | cut -c6 \` != \"-\" ]; then
      echo \"Group Write permission set on directory \$1\"
    fi
    if [ \`echo \$dirperm | cut -c9 \` != \"-\" ]; then
      echo \"Other Write permission set on directory \$1\"
    fi
    dirown=\`ls -ldH \$1 | awk '{print \$3}'\`
    if [ \"$dirown\" != \"root\" ] ; then
      echo \$1 is not owned by root
    fi
  else
    echo \$1 is not a directory
	fi
	shift
done\n

		Remediation:
		Correct or justify any items discovered in the Audit step."


fi
}

ensure_all_users_home_directories_exist () {
		echo -e "\e[92m== 6.2.7 Ensure all users' home directories exist ==\n"
		output=$(cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  		if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
    		echo "The home directory ($dir) of user $user does not exist."
  	fi
done)

		if [[ $output = "" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n
		$output \n

		Audit:
		Run the following script and verify no results are returned:

#!/bin/bash
cat /etc/passwd | awk -F: '{ print \$1 \" \" \$3 \" \" \$6 }' | while read user uid dir; do
  if [ \$uid -ge 1000 -a ! -d \"$dir\" -a \$user != \"nfsnobody\" ]; then
    echo \"The home directory (\$dir) of user \$user does not exist.\"
  fi
done\n

		Remediation:
		If any users' home directories do not exist, create them and make sure the respective user owns the directory. Users without an assigned home directory should be removed or assigned a home directory as appropriate.\n"

	fi
}

ensure_users_home_directories_permissions_are_750_or_more_restrictive () {
		echo -e "\e[92m== 6.2.8 Ensure users' home directories permissions are 750 or more restrictive ==\n"
		output=$(for dir in `cat /etc/passwd  | egrep -v '(root|halt|sync|shutdown)' 2>/dev/null | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
  dirperm=`ls -ld $dir 2>/dev/null | cut -f1 -d " "`
  if [ "`echo $dirperm | cut -c6 `" != "-" ]; then
    echo "Group Write permission set on directory $dir"
  fi
  if [ "`echo $dirperm | cut -c8 `" != "-" ]; then
echo "Other Read permission set on directory $dir"
  fi
  if [ "`echo $dirperm | cut -c9 `" != "-" ]; then
    echo "Other Write permission set on directory $dir"
  fi
  if [ "`echo $dirperm | cut -c10 `" != "-" ]; then
    echo "Other Execute permission set on directory $dir"
  fi
done)

		if [[ $output = "" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n
$output

		Audit:
		Run the following script and verify no results are returned:

#!/bin/bash
for dir in \`cat /etc/passwd  | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != \"/usr/sbin/nologin\") { print $6 }'\`; do
  dirperm=`ls -ld \$dir | cut -f1 -d" "`
  if [ \`echo \$dirperm | cut -c6 \` != \"-\" ]; then
    echo \"Group Write permission set on directory \$dir\"
  fi
  if [ \`echo \$dirperm | cut -c8 \` != \"-\" ]; then
echo \"Other Read permission set on directory \$dir\"
  fi
  if [ \`echo \$dirperm | cut -c9 \` != \"-\" ]; then
    echo \"Other Write permission set on directory \$dir\"
  fi
  if [ \`echo \$dirperm | cut -c10 \` != \"-\" ]; then
    echo \"Other Execute permission set on directory \$dir\"
  fi
done\n

		Remediation:
		Making global modifications to user home directories without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user file permissions and determine the action to be taken in accordance with site policy.\n"

	fi
}

ensure_users_own_their_home_directories () {
		echo -e "\e[92m== 6.2.9 Ensure users own their home directories ==\n"
		output=$(cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
		 if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then
			  owner=$(stat -L -c "%U" "$dir")
			   if [ "$owner" != "$user" ]; then
				    echo "The home directory ($dir) of user $user is owned by $owner."
				     fi
				      fi
			      done)

		if [[ $output = "" ]]
                                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n
$output

		Audit:
		Run the following script and verify no results are returned:

#!/bin/bash
cat /etc/passwd | awk -F: '{ print \$1 \" \" \$3 \" \" \$6 }' | while read user uid dir; do
 if [ \$uid -ge 1000 -a -d \"\$dir\" -a \$user != \"nfsnobody\" ]; then
 owner=\$(stat -L -c \"%U\" \"\$dir\")
 if [ \"\$owner\" != \"\$user\" ]; then
 echo \"The home directory (\$dir) of user \$user is owned by \$owner.\"\n

 fi
 fi
done

		Remediation:
		Change the ownership of any home directories that are not owned by the defined user to the correct user.\n"


	fi
}

ensure_users_dot_files_are_not_group_or_world_writable () {
		echo -e "\e[92m== 6.2.10 Ensure users' dot files are not group or world writable ==\n"
output=$(for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
  for file in $dir/.[A-Za-z0-9]*; do
    if [ ! -h "$file" -a -f "$file" ]; then
      fileperm=`ls -ld $file 2>/dev/null | cut -f1 -d" "`
      if [ `echo $fileperm | cut -c6 ` != "-" ]; then
        echo "Group Write permission set on file $file"
fi
if [ `echo $fileperm | cut -c9 ` != "-" ]; then
        echo "Other Write permission set on file $file"
fi
fi
done
done)

		if [[ $output = "" ]]
	        then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n

$output

		Audit:
		Run the following script and verify no results are returned:
#!/bin/bash
for dir in \`cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'\`; do
  for file in \$dir/.[A-Za-z0-9]*; do
    if [ ! -h \"\$file\" -a -f \"\$file\" ]; then
      fileperm=\`ls -ld \$file | cut -f1 -d\" \"\`
      if [ \`echo \$fileperm | cut -c6 \` != \"-\" ]; then
        echo \"Group Write permission set on file \$file\"
fi
if [ \`echo \$fileperm | cut -c9 \` != \"-\" ]; then
        echo \"Other Write permission set on file \$file\"
fi
fi
done
done\n

		Remediation:
		Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user dot file permissions and determine the action to be taken in accordance with site policy.\n"

	fi

}

ensure_no_users_have_forward_files () {
		echo -e "\e[92m== 6.2.11 Ensure no users have .forward files ==\n"
		output=$(for dir in `cat /etc/passwd |\
			  awk -F: '{ print $6 }'`; do
		  if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
			      echo ".forward file $dir/.forward exists"
			        fi
			done)

		if [[ $output = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n

$output

                Audit:
		Run the following script and verify no results are returned:

		#!/bin/bash
		for dir in \`cat /etc/passwd |\
			  awk -F: '{ print \$6 }'\`; do
		  if [ ! -h \"\$dir/.forward\" -a -f \"\$dir/.forward\" ]; then
			      echo \".forward file \$dir/.forward exists\"
			        fi
			done


		Remediation:
		Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user .forward files and determine the action to be taken in accordance with site policy.\n"


	fi
}

ensure_no_users_have_netrc_files () {
		echo -e "\e[92m== 6.2.12 Ensure no users have .netrc files ==\n"
		output=$(for dir in `cat /etc/passwd |\
			  awk -F: '{ print $6 }'`; do
		  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
			      echo ".netrc file $dir/.netrc exists"
			        fi
			done)

		if [[ $output = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n

$output

                Audit:
		Run the following script and verify no results are returned:

#!/bin/bash
for dir in \`cat /etc/passwd |\
  awk -F: '{ print \$6 }'\`; do
  if [ ! -h \"\$dir/.netrc\" -a -f \"\$dir/.netrc\" ]; then
    echo \".netrc file \$dir/.netrc exists\"
  fi
done


		Remediation:
		Making global modifications to users' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user .netrc files and determine the action to be taken in accordance with site policy.\n"

	fi
}

ensure_users_netrc_files_are_not_group_or_world_accessible () {
		echo -e "\e[92m== 6.2.13 Ensure users' .netrc Files are not group or world accessible ==\n"
		output=$(for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
  for file in $dir/.netrc; do
    if [ ! -h "$file" -a -f "$file" ]; then
      fileperm=`ls -ld $file 2>/dev/null | cut -f1 -d" "`
      if [ "`echo $fileperm | cut -c5 `" != "-" ]; then
        echo "Group Read set on $file"
fi
      if [ "`echo $fileperm | cut -c6 `" != "-" ]; then
        echo "Group Write set on $file"
      fi
      if [ "`echo $fileperm | cut -c7 `" != "-" ]; then
        echo "Group Execute set on $file"
      fi
      if [ "`echo $fileperm | cut -c8 `" != "-" ]; then
        echo "Other Read  set on $file"
      fi
      if [ "`echo $fileperm | cut -c9 `" != "-" ]; then
        echo "Other Write set on $file"
      fi
      if [ "`echo $fileperm | cut -c10 `" != "-" ]; then
        echo "Other Execute set on $file"
      fi
fi done
done)

		if [[ $output = "" ]]
		then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n

$output

                Audit:
		Run the following script and verify no results are returned:
#!/bin/bash
for dir in \`cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '(\$7 != \"/usr/sbin/nologin\") { print \$6 }'\`; do
  for file in \$dir/.netrc; do
    if [ ! -h \"\$file\" -a -f \"\$file\" ]; then
      fileperm=\`ls -ld \$file | cut -f1 -d\" \"\`
      if [ \`echo \$fileperm | cut -c5 \` != \"-\" ]; then
        echo \"Group Read set on \$file\"
fi
      if [ \`echo \$fileperm | cut -c6 \` != \"-\" ]; then
        echo \"Group Write set on \$file\"
      fi
      if [ \`echo \$fileperm | cut -c7 \` != \"-\" ]; then
        echo "Group Execute set on \$file"
      fi
      if [ \`echo \$fileperm | cut -c8 \` != \"-\" ]; then
        echo "Other Read  set on \$file"
      fi
      if [ \`echo \$fileperm | cut -c9 \` != \"-\" ]; then
        echo "Other Write set on \$file"
      fi
      if [ \`echo \$fileperm | cut -c10 \` != \"-\" ]; then
        echo \"Other Execute set on \$file\"
      fi
fi done
done


		Remediation:
		Making global modifications to users\' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user .netrc file permissions and determine the action to be taken in accordance with site policy.

		Notes:
		While the complete removal of .netrc files is recommended if any are required on the system secure permissions must be applied.\n"

	fi
}

ensure_no_users_have_rhost_files () {
		echo -e "\e[92m== 6.2.14 Ensure no users have .rhosts files ==\n"
		output=$(for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
		  for file in $dir/.rhosts; do
			      if [ ! -h "$file" -a -f "$file" ]; then
				            echo ".rhosts file in $dir"
					        fi
					done
				done)

		if [[ $output = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n

$output

                Audit:
		Run the following script and verify no results are returned:
	#!/bin/bash
	for dir in \`cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '(\$7 != \"/usr/sbin/nologin\") { print \$6 }'\`; do
	  for file in \$dir/.rhosts; do
	      if [ ! -h \"\$file\" -a -f \"\$file\" ]; then
	          echo \".rhosts file in \$dir\"
        fi
done
done


		Remediation:
		Making global modifications to users\' files without alerting the user community can result in unexpected outages and unhappy users. Therefore, it is recommended that a monitoring policy be established to report user .rhosts files and determine the action to be taken in accordance with site policy.\n"

	fi
}

ensure_all_groups_in_etc_passwd_exist_in_etc_group () {
		echo -e "\e[92m== 6.2.15  Ensure all groups in /etc/passwd exist in /etc/group ==\n"
		output=$(for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
		  grep -q -P "^.*?:[^:]*:$i:" /etc/group
		    if [ $? -ne 0 ]; then
			        echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
				  fi
			  done)

		if [[ $output = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n

$output

                Audit:
		Run the following script and verify no results are returned:
		#!/bin/bash
		for i in \$(cut -s -d: -f4 /etc/passwd | sort -u ); do
			  grep -q -P \"^.*?:[^:]*:\$i:\" /etc/group
			    if [ \$? -ne 0 ]; then
				        echo \"Group \$i is referenced by /etc/passwd but does not exist in /etc/group\"
					  fi
				  done


		Remediation:
		Analyze the output of the Audit step above and perform the appropriate action to correct any discrepancies found.\n"

	fi
}

ensure_no_duplicate_uids_exist () {
		echo -e "\e[92m== 6.2.16 Ensure no duplicate UIDs exist ==\n"
		output=$(cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
		  [ -z "${x}" ] && break
		    set - $x
		      if [ $1 -gt 1 ]; then
			          users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
				      echo "Duplicate UID ($2): ${users}"
				        fi
				done)


		if [[ $output = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n

$output

		Audit:
		Run the following script and verify no results are returned:
#!/bin/bash
cat /etc/passwd | cut -f3 -d\":\" | sort -n | uniq -c | while read x ; do
  [ -z \"\${x}\" ] && break
  set - \$x
  if [ \$1 -gt 1 ]; then
    users=\`awk -F: '(\$3 == n) { print \$1 }' n=\$2 /etc/passwd | xargs\`
    echo \"Duplicate UID (\$2): \${users}\"
  fi
done

		Remediation:
		Based on the results of the audit script, establish unique UIDs and review all files owned by the shared UIDs to determine which UID they are supposed to belong to.\n"

	fi

}

ensure_no_duplicate_gids_exist () {
		echo -e "\e[92m== 6.2.17 Ensure no duplicate GIDs exist ==\n"
		output=$(cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
		  [ -z "${x}" ] && break
		    set - $x
		      if [ $1 -gt 1 ]; then
			          groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
				      echo "Duplicate GID ($2): ${groups}"
				        fi
				done)

		if [[ $output = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n

$output

                Audit:
		Run the following script and verify no results are returned:

#!/bin/bash
cat /etc/group | cut -f3 -d\":\" | sort -n | uniq -c | while read x ; do
  [ -z \"\${x}\" ] && break
    set - \$x
      if [ \$1 -gt 1 ]; then
	          groups=\`awk -F: '(\$3 == n) { print \$1 }' n=\$2 /etc/group | xargs\`
		      echo \"Duplicate GID (\$2): \${groups}\"
		        fi
		done


		Remediation:
		Based on the results of the audit script, establish unique GIDs and review all files owned by the shared GID to determine which group they are supposed to belong to.\n

		Notes:
		You can also use the grpck command to check for other inconsistencies in the /etc/group file.\n"

	fi
}

ensure_no_duplicate_user_names_exist () {
		echo -e "\e[92m== 6.2.18 Ensure no duplicate user names exist ==\n"
		output=$(cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
		  [ -z "${x}" ] && break
		    set - $x
		      if [ $1 -gt 1 ]; then
			          uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
				      echo "Duplicate User Name ($2): ${uids}"
			      fi done)

		if [[ $output = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n

$output

		Audit:
		Run the following script and verify no results are returned:

		#!/bin/bash
		cat /etc/passwd | cut -f1 -d\":\" | sort -n | uniq -c | while read x ; do
		  [ -z \"\${x}\" ] && break
		    set - \$x
		      if [ \$1 -gt 1 ]; then
			          uids=\`awk -F: '(\$1 == n) { print \$3 }' n=\$2 /etc/passwd | xargs\`
				      echo \"Duplicate User Name (\$2): \${uids}\"
			      fi
		      done


		Remediation:
		Based on the results of the audit script, establish unique user names for the users. File ownerships will automatically reflect the change as long as the users have unique UIDs.\n"

	fi

}

ensure_no_duplicate_group_names_exist () {
		echo -e "\e[92m== 6.2.19 Ensure no duplicate group names exist ==\n"
		output=$(cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
		  [ -z "${x}" ] && break
		    set - $x
		      if [ $1 -gt 1 ]; then
			          gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
				      echo "Duplicate Group Name ($2): ${gids}"
			      fi done)

		if [[ $output = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n

$output

		Audit:
	Run the following script and verify no results are returned:
#!/bin/bash
cat /etc/group | cut -f1 -d\":\" | sort -n | uniq -c | while read x ; do
  [ -z \"\${x}\" ] && break
    set - \$x
      if [ \$1 -gt 1 ]; then
	          gids=\`gawk -F: \'(\$1 == n) { print \$3 }\' n=\$2 /etc/group | xargs\`
		      echo \"Duplicate Group Name (\$2): \${gids}\"
	      fi done

	      Remediation:
	      Based on the results of the audit script, establish unique names for the user groups. File group ownerships will automatically reflect the change as long as the groups have unique GIDs.\n"

      fi
}

ensure_shadow_group_is_empty () {
		echo -e "\e[92m== 6.2.20 Ensure shadow group is empty ==\n"
		if [[ "$(grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group 2>/dev/null)" = "" && "$(awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd)" = "" ]]
                then echo -e "Passed!\n"
                else
                echo -e "\e[31mFailed!\e[0m : \n                Audit:
		Run the following commands and verify no results are returned:
		# grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group
		# awk -F: '(\$4 == \"<shadow-gid>\") { print }' /etc/passwd

		Remediation:
		Remove all users from the shadow group, and change the primary group of any users with shadow as their primary group.	\n"

	fi

}


echo -e "\e[92m== 1. Initial Setup =="
echo -e "\e[92m== 1.1 Filesystem Configuration =="
echo -e "\e[92m== 1.1.1 Disable unused filesystems =="
disable_cramfs
disable_freevxfs
disable_jffs2
disable_hfs
disable_hfsplus
disable_squashfs
disable_udf
disable_fat
tmp_on_own_partition
tmp_nodev
tmp_nosuid
var_on_own_partition
var_tmp_on_own_partition
var_tmp_nodev
var_tmp_nosuid
var_tmp_noexec
var_log_on_own_partition
var_log_audit_on_own_partition
home_on_own_partition
home_nodev
dev_shm_nodev
dev_shm_nosuid
dev_shm_noexec
removable_media_nosuid
removable_media_noexec
sticky_bit_set_on_world_writable_directories
disable_automounting

echo -e "\n\e[92m== 1.2 Configure Software Updates ==\e\n"
ensure_package_manager_repos_are_configured
ensure_gpg_keys_are_configured


echo -e "\n\e[92m== 1.3 Filesystem Integrity Checking ==\e\n"
ensure_aide_is_installed
ensure_filesystem_integrity_is_regularly_checked

echo -e "\e[92m== 1.4 Secure Boot Settings =="
ensure_permissions_on_bootloader
ensure_bootloader_password
ensure_auth_required_for_single_user_mode

echo -e "\e[92m== 1.5 Additional Process Hardening ==\e\n"
ensure_core_dumps_are_restricted
ensure_xd_nd_support_is_disabled
ensure_address_space_layout_randomization
ensure_prelink_is_disabled

echo -e "\e[92m== 1.6  Mandatory Access Control ==\e\n"
echo -e "\e[92m== 1.6.1 Configure SELinux ==\e\n"
ensure_selinux_is_not_disabled_in_bootloader
ensure_selinux_state_is_enforcing
ensure_selinux_policy_is_configured
ensure_no_unconfined_daemons_exist

echo -e "\e[92m== 1.6.2 Configure AppArmor ==\e\n"
ensure_apparmor_is_not_disabled_in_bootloader
ensure_all_apparmor_profiles_are_enforcing
ensure_selinux_or_apparmor_are_installed

echo -e "\e[92m== 1.7 Warning Banners ==\e\n"
echo -e "\e[92m== 1.7.1 Command Line Warning Banners ==\e\n"
ensure_message_of_the_day_is_configured
ensure_local_login_warning_banner_is_configured_properly
ensure_remote_login_warning_banner_is_configured
ensure_permissions_on_etc_motd_are_configured
ensure_permissions_on_etc_issue_are_configured
ensure_permissions_on_etc_issue_net_are_configured
ensure_gdm_login_banner_is_configured
ensure_updates_patches_and_additional_security

echo -e "\e[92m== 2 Services ==\e\n"
ensure_chargen_services_are_not_enabled
ensure_daytime_services_are_not_enabled
ensure_discard_services_are_not_enabled
ensure_echo_services_are_not_enabled
ensure_time_services_are_not_enabled
ensure_rsh_server_is_not_enabled
ensure_talk_server_is_not_enabled
ensure_telnet_server_is_not_enabled
ensure_tftpt_server_is_not_enabled
ensure_xinetd_is_not_enabled

echo -e "\e[92m== 2.2 Special Purpose Services ==\n"
echo -e "\e[92m== 2.2.1 Time Synchronization ==\n"
ensure_time_synchronization_is_in_use
ensure_ntp_is_configured
ensure_chrony_is_configured
ensure_x_window_system_is_not_installed
ensure_avahi_server_is_not_installed
ensure_cups_is_not_enabled
ensure_dhcp_server_is_not_enabled
ensure_ldap_server_is_not_enabled
ensure_nfs_and_rpc_are_not_enabled
ensure_dns_server_is_not_enabled
ensure_ftp_server_is_not_enabled
ensure_http_server_is_not_enabled
ensure_imap_and_pop3_server_is_not_enabled
ensure_samba_is_not_enabled
ensure_http_proxy_server_is_not_enabled
ensure_snmp_server_is_not_enabled
ensure_mail_transfer_agent_is_configured_for_local_only
ensure_rsync_service_is_not_enabled
ensure_nis_server_is_not_enabled

echo -e "\e[92m== 2.3 Service Clients ==\n"
ensure_nis_client_is_not_installed
ensure_rsh_client_is_not_installed
ensure_talk_client_is_not_installed
ensure_telnet_client_is_not_installed
ensure_ldap_client_is_not_installed

echo -e "\e[92m== 3 Network Configuration ==\n"
echo -e "\e[92m== 3.1 Network Parameters \(Host Only\) ==\n"
ensure_ip_forwarding_is_disabled
ensure_packet_redirect_sending_is_disabled

echo -e "\e[92m== 3.2 Network Parameters \(Host and Router\) ==\n"
ensure_source_routed_packets_are_not_accepted
ensure_icmp_redirects_are_not_accepted
ensure_secure_icmp_redirects_are_not_accepted
ensure_suspicious_packets_are_logged
ensure_broadcast_icmp_requests_are_ignored
ensure_bogus_icmp_responses_are_ignored
ensure_reverse_path_filtering_is_enabled
ensure_tcp_syn_cookies_is_enabled

echo -e "\e[92m== 3.3 IPv6 ==\n"
ensure_ipv6_router_advertisements_are_not_accepted
ensure_ipv6_redirects_are_not_accepted
ensure_ipv6_is_disabled

echo -e "\e[92m== 3.4 TCP Wrappers ==\n"
ensure_tcp_wrappers_is_installed
ensure_etc_hosts_allow_is_configured
ensure_etc_hosts_deny_is_configured
ensure_permissions_on_etc_hosts_allow_are_configured
ensure_permissions_on_etc_hosts_deny

echo -e "\e[92m== 3.5 Uncommon Network Protocols ==\n"
ensure_dccp_is_disabled
ensure_sctp_is_disabled
ensure_rds_is_disabled
ensure_tipc_is_disabled

echo -e "\e[92m== 3.6 Firewall Configuration ==\n"
ensure_iptables_is_installed
ensure_default_deny_firewall_policy
ensure_looopback_traffic_is_configured
ensure_outbound_and_established_connections_are_configured
ensure_firewall_rules_exist_for_all_open_ports
ensure_wireless_interfaces_are_disabled

echo -e "\e[92m== 4 Logging and Auditing ==\n"
echo -e "\e[92m== 4.1 Configure System Accounting \(auditd\) ==\n"
echo -e "Note: Once all configuration changes have been made to /etc/audit/audit.rules, the auditd configuration must be reloaded:
# service auditd reload\n"
echo -e "\e[92m== 4.1.1 Configure Data Retention ==\n"
ensure_audit_log_storage_size_is_configured
ensure_system_is_disabled_when_audit_logs_are_full
ensure_audit_logs_are_not_automatically_deleted
ensure_auditd_service_is_enabled
ensure_auditing_for_processes_that_start_prior_to_auditd_is_enabled
ensure_events_that_modify_date_and_time_info_are_collected
ensure_events_that_modify_user_group_info_are_collected
ensure_events_that_modify_the_systems_network_env_are_collected
ensure_events_that_modify_the_systems_manditory_access_controls_are_collected
ensure_login_and_logout_events_are_collected
ensure_session_initiation_information_is_collected
ensure_discretionary_access_control_permission_mod_events_are_collected
ensure_unsuccessful_unauthorized_file_access_attempts_are_collected
ensure_use_of_privileged_commands_is_collected
ensure_successful_file_system_mounts_are_collected
ensure_file_deletion_events_by_users_are_collected
ensure_changes_to_system_administration_scope_is_collected
ensure_system_administrator_actions_sudolog_are_collected
ensure_kernel_module_loading_and_unloading_is_collected
ensure_the_audit_configuration_is_immutable
echo -e "\e[92m== 4.2 Configure Logging ==\n"
echo -e "\e[92m== 4.2.1 Configure rsyslog ==\n"
ensure_rsyslog_service_is_enabled
ensure_logging_is_configured
ensure_rsyslog_default_file_permissions_configured
ensure_rsyslog_is_configured_to_send_logs_to_remote_host
ensure_remote_rsyslog_messages_are_only_accepted_on_designated_log_hosts
echo -e "\e[92m== 4.2.2 Configure syslog-ng ==\n"
ensure_syslog_ng_service_is_enabled
ensure_syslog_ng_logging_is_configured
ensure_syslog_ng_default_file_permissions_configured
ensure_syslog_ng_is_configured_to_send_logs_to_remote_host
ensure_remote_syslog_ng_messages_are_only_accepted_on_designated_hosts
ensure_rsyslog_or_syslog_ng_is_installed
ensure_permissions_on_all_logfiles_are_configured
ensure_logrotate_is_configured

echo -e "\e[92m== 5 Access, Authentication and Authorization ==\n"
echo -e "\e[92m== 5.1 Configure cron ==\n"
ensure_cron_daemon_is_enabled
ensure_permissions_on_etc_crontab_are_configured
ensure_permissions_on_etc_cron_hourly_are_configured
ensure_permissions_on_etc_cron_daily_are_configured
ensure_permissions_on_etc_cron_weekly_are_configured
ensure_permissions_on_etc_cron_monthly_are_configured
ensure_permissions_on_etc_cron_d_are_configured
ensure_at_cron_is_restricted_to_authorized_users

echo -e "\e[92m== 5.2 SSH Server Configuration ==\n"
ensure_permissions_on_etc_ssh_sshd_config_are_configured
ensure_ssh_protocol_is_set_to_2
ensure_ssh_loglevel_is_set_to_info
ensure_ssh_x11_forwarding_is_disabled
ensure_ssh_MaxAuthTries_is_set_to_4_or_less
ensure_ssh_IgnoreRhosts_is_enabled
ensure_ssh_hostbasedAuthentication_is_disabled
ensure_ssh_root_login_is_disabled
ensure_ssh_PermitEmptyPasswords_is_disabled
ensure_ssh_PermitUserEnvironment_is_disabled
ensure_only_approved_mac_algorithms_are_used
ensure_ssh_idle_timeout_interval_is_configured
ensure_ssh_LoginGraceTime_is_set_to_one_minute_or_less
ensure_ssh_access_is_limited
ensure_ssh_warning_banner_is_configured

echo -e "\e[92m== 5.3 Configure PAM ==\n"
ensure_password_creation_requirements_are_configured
ensure_lockout_for_failed_password_attempts_is_configured
ensure_password_reuse_is_limited
ensure_password_hashing_algorithm_is_sha_512

echo -e "\e[92m== 5.4 User Accounts and Environment ==\n"
echo -e "\e[92m== 5.4.1 Set Shadow Password Suite Parameters ==\n"
ensure_password_expiration_is_90_days_or_less
ensure_minimum_days_between_password_change_is_7_days_or_more
ensure_password_expiration_warning_is_7_days_or_more
ensure_inactive_password_lock_is_30_days_or_less
ensure_system_accounts_are_non_login
ensure_default_group_for_root_account_is_gid_0
ensure_default_user_umask_is_027_or_more_restrictive
ensure_root_login_is_restricted_to_system_console
ensure_access_to_the_su_command_is_restricted

echo -e "\e[92m== 6 System Maintenance ==\n"
echo -e "\e[92m== 6.1 System File Permissions ==\n"
audit_system_file_permissions
ensure_permissions_on_etc_passwd_are_configured
ensure_permissions_on_etc_shadow_are_configured
ensure_permissions_on_etc_group_are_configured
ensure_permissions_on_etc_gshadow_are_configured
ensure_permissions_on_etc_passwd__are_configured
ensure_permissions_on_etc_shadow__are_configured
ensure_permissions_on_etc_group__are_configured
ensure_permissions_on_etc_gshadow__are_configured
ensure_no_world_writable_files_exist
ensure_no_unowned_files_or_directories_exist
ensure_no_ungrouped_files_or_directories_exist
audit_suid_executables
audit_sgid_executables

echo -e "\e[92m== 6.2 User and Group Settings ==\n"
ensure_password_fields_are_not_empty
ensure_no_legacy_+_entries_exist_in_etc_passwd
ensure_no_legacy_+_entries_exist_in_etc_shadow
ensure_no_legacy_+_entries_exist_in_etc_group
ensure_root_is_the_only_uid_0_account
ensure_root_path_integrity
ensure_all_users_home_directories_exist
ensure_users_home_directories_permissions_are_750_or_more_restrictive
ensure_users_own_their_home_directories
ensure_users_dot_files_are_not_group_or_world_writable
ensure_users_dot_files_are_not_group_or_world_writable
ensure_no_users_have_forward_files
ensure_no_users_have_netrc_files
ensure_users_netrc_files_are_not_group_or_world_accessible
ensure_no_users_have_rhost_files
ensure_all_groups_in_etc_passwd_exist_in_etc_group
ensure_no_duplicate_uids_exist
ensure_no_duplicate_gids_exist
ensure_no_duplicate_user_names_exist
ensure_no_duplicate_group_names_exist
ensure_shadow_group_is_empty



echo -e "\e[0m"
