result="result.txt"
#취약점 발견시 카운트 상승
Total_vulc=0
Rev=0

#U-01
U_01(){
    if [ -f /etc/ssh/sshd_config ]; then
        check=`grep -iE '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config | awk -F'[ =]+' '{print $2}'`
        if [ "$check" != "no" ]; then
            echo "U_01 취약: sshd PermitRootLogin 허용 설정 발견" >> $result
            ((Total_vulc++))
        fi
    fi

    if [ -f /etc/securetty ]; then
        size=$(wc -c /etc/securetty | awk '{print $1}')
        if [ $size -ne 0 ]; then
            echo "U_01 취약: /etc/securetty에 내용 존재" >> $result
            ((Total_vulc++))
        fi
    else
        echo "U_01 검토 : /etc/securetty가 존재하지 않아 로그인 차단 미적용" >> $result
        ((Rev++))

    fi
}

#U_02
U_02(){
    if [ -f /etc/security/pwquality.conf ]; then
        parameters=("lcredit" "ucredit" "dcredit" "ocredit" "minlen" "difok") 
        for ((i=0; i<${#parameters[@]}; i++))
        do
            param=${parameters[$i]}
            check=$(grep -iE "^[[:space:]]*${param}" /etc/security/pwquality.conf \
                    | tr -d '[:space:]' \
                    | awk -F '=' '{print $2}')

            # 값이 없으면 취약
            if [ -z "$check" ]; then
                echo "U_02 취약: $param 미설정" >> $result
                ((Total_vulc++))
                continue
            fi

            # minlen 검사
            if [ "$param" = "minlen"  ]; then
                if [ "$check" -lt 8 ]; then
                    echo "U_02 취약: 최소 패스워드 길이 부족" >> $result
                    ((Total_vulc++))
                fi

            # difok 비어 있는 경우 취약
            elif [ "$param" = "difok"  ]; then
                if [ "$check" -lt 1 ]; then
                    echo "U_02 취약: 동일 패스워드 사용 불가 수준 미달 (difok)" >> $result
                    ((Total_vulc++))
                fi

            # credit 계열
            else
                if [ "$check" -gt -1 ]; then
                    echo "U_02 취약: $param 값 이상 발견" >> $result
                    ((Total_vulc++))
                fi
            fi
        done
    else
        echo "U_02 검토 : /etc/security/pwquality.conf가 존재하지 않음" >> $result
        ((Rev++))
    fi

}
U_03(){
    if [ -f /etc/pam.d/common-auth ]; then
        mapfile -t denycounts < <(grep -vE '^[[:space:]]*#' /etc/pam.d/common-auth | awk 'match($0, /deny[[:space:]]*=?[[:space:]]*[0-9]+/) { s=substr($0,RSTART,RLENGTH); gsub(/[^0-9]/,"",s); print s }')
        for row in "${denycounts[@]}"; do
            if [ "$row" -le 10 ]; then
                echo "U-03 취약: 계정 잠금 임계값이 설정되어 있지 않거나 10회 이하의 값으로 설정되어 있습니다." >> $result
                ((Total_vulc++))
                break
            fi
        done
    else
        echo "U-03 검토 : /etc/pam.d/common-auth가 존재하지 않음" >> $result
        ((Rev++))
    fi
}

U_04(){
    while IFS= read -r line
    do
        user=$(echo "$line" | awk -F ':' '{print $1}')
        pw=$(echo "$line" | awk -F ':' '{print $2}')
        if [[ "$pw" != "x" ]]; then
            echo "U-04 취약: passwd파일에 $user (pw='$pw')" >> $result
            ((Total_vulc++))
        fi
        
    done < /etc/passwd
}

U_05(){
    InvalidUser=$(awk -F : '$3 == 0 && $1 != "root" {print $1}' /etc/passwd )
    if [ -z "$InvalidUser" ]; then
        echo "U-05 취약 : root를 제외하고 uid가 0인 계정 존재 /etc/passwd" >> $result
        ((Total_vulc++))
    fi
}

U_06(){
    sugroup=("wheel")
    count=0
    mapfile -t check < <(grep -vE '^[[:space:]]*#' /etc/pam.d/su 2>/dev/null | grep -E 'pam_wheel\.so' | sed -n 's/.*group[[:space:]]*=[[:space:]]*\([^ ]*\).*/\1/p')
    if [ ${#check[@]} -eq 0 ]; then
        echo "U-06 검토 : /etc/pam.d/su에 pam_wheel(group=) 설정이 존재하지 않음" >> $result
        ((Rev++))
        return
    fi
    for x in ${check[@]}; do
        count=0
        for y in "${sugroup[@]}"; do
            if [ "$x" == "$y" ]; then
                count=1
            fi
            if [ "$count" -eq 1 ]; then
                break
            fi
        done
        if  [ "$count" -eq 0 ]; then
            echo "U-06 취약: /etc/pam.d/su 파일에 $x 그룹이 su 사용 그룹으로 설정됨" >> $result
            ((Total_vulc++))
        fi
    done

}

U_07(){
    mapfile -t users < <(awk -F : '$7=="/bin/bash"{print $1}' /etc/passwd)
    for user in "${users[@]}"; do
        logs=$(last $user --since "3 months ago"| grep -v '^wtmp begins' | wc -l)
        if [ "$logs" -gt 1 ]; then
            echo "U-07 검토: 로그인 가능한 사용자 중에 3개월 이상 사용되지 않은 계정이 있음 ($user)" >> $result
            ((Rev++))
        fi
    done
}

U_08(){
    if grep '^root:' /etc/group | tr ',' '\n' | grep -v '^root$' | grep -q .; then
        echo "U-08 취약 root 그룹에 root 외의 사용자 존재" >> $result
        ((Total_vulc++))
    fi
}

U_09(){
    mapfile -t groups < <(awk -F : '{print $1}' /etc/group)
    for group in "${groups[@]}"; do
        gfile=$(find / -group $group 2>/dev/null | wc -l)
        if [ "$gfile" -eq 0 ]; then
            echo "U-09 검토: 불필요한것으로 의심되는 그룹 발견 ($group)" >> $result
            ((Rev++))
        fi
    done
}

U_10(){
    mapfile -t duplications < <(awk -F : '{print $3}' /etc/passwd | sort | uniq -d)
    echo "U-10 취약: 중복되는 UID 발견 ${duplications[@]}" >> $result
    ((Total_vulc++))
}

U_11(){
    noneeds=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")
    for noneed in "${noneeds[@]}"; do
        check=$(awk -F : '$1==$noneed {print $7}' /etc/passwd)
        if [ "$check"!="/bin/false" ] && [ "$check"!="/sbin/nologin" ]; then
            echo "U-11 취약: 로그인이 필요하지않은 계정에 /bin/false 혹은 /sbin/nologin이 부여되어 있지 않음 ($noneed)" >> $result
            ((Total_vulc++))
        fi
    done
}

U_12() {
    local limit=600
    local files=(
        "/etc/profile"
        "/etc/bash.bashrc"
    )

    # /etc/profile.d/*.sh 추가
    if [ -d /etc/profile.d ]; then
        while IFS= read -r f; do files+=( "$f" ); done < <(find /etc/profile.d -maxdepth 1 -type f -name "*.sh" 2>/dev/null)
    fi

    # TMOUT=숫자 형태만 추출(주석 제외), 파일:값 형태로 저장
    mapfile -t checks < <(
        awk '
            /^[[:space:]]*#/ { next }  # 주석 제거
            match($0, /^[[:space:]]*TMOUT[[:space:]]*=[[:space:]]*[0-9]+/) {
                s=substr($0, RSTART, RLENGTH)
                gsub(/^[[:space:]]*TMOUT[[:space:]]*=[[:space:]]*/, "", s)
                print FILENAME ":" s
            }
        ' "${files[@]}" 2>/dev/null
    )

    if [ ${#checks[@]} -eq 0 ]; then
        echo "U-12 취약: 시스템 전역 쉘 환경설정에서 TMOUT 설정을 찾지 못함" >> "$result"
        ((Total_vulc++))
        return
    fi

    for row in "${checks[@]}"; do
        local file="${row%%:*}"
        local val="${row##*:}"

        # 숫자 검증
        if ! [[ "$val" =~ ^[0-9]+$ ]]; then
            echo "U-12 검토: $file 에서 TMOUT 값이 숫자가 아님($val)" >> "$result"
            ((Rev++))
            continue
        fi

        # 기준: 600초 초과면 취약
        if [ "$val" -gt "$limit" ]; then
            echo "U-12 취약: $file 에서 TMOUT=$val (기준 ${limit}초 초과)" >> "$result"
        fi
    done
}

U_13(){
    ENCRYPT_METHOD=$(grep -vE '^[[:space:]]*#' /etc/login.defs | grep 'ENCRYPT_METHOD' | awk '{print $2}')
    if [ "$ENCRYPT_METHOD" != "SHA-256" ] && [ "$ENCRYPT_METHOD" != "SHA-512" ] && [ "$ENCRYPT_METHOD" != "yescrypt" ]; then
        echo "U-13 취약: /etc/login.defs 에서 적절하지 못한 암호화 설정 발견 ($ENCRYPT_METHOD)" >> $result
        ((Total_vulc++))
    fi
    if ! grep -vE '^[[:space:]]*#' /etc/pam.d/common-password 2>/dev/null | grep 'pam_unix.so' | grep -Eq 'sha512|sha256|yescrypt'; then
        echo "U-13 취약: /etc/pam.d/common-password에 암호화 알고리즘 설정이 부적절함" >> $result
        ((Total_vulc++))
    fi

}

U_14(){
    if echo "$PATH" | grep -Eq '(^|:)\.(\:|$)|::'; then
        echo "U-14 취약: PATH에 현재 디렉터리(.) 또는 빈 경로(::)가 포함되어 있음" >> "$result"
        ((Total_vulc++))
    fi
}

U_15(){
    count=$(find / \( -nouser -or -nogroup \) 2>/dev/null | wc -l)
    if [ $count -ne 0 ]; then
        echo "U-06 취약: 소유자가 없거나 소유 그룹이 존재하지 않는 파일 발견" >> $result
        echo $(find / \( -nouser -or -nogroup \) 2>/dev/null) >> $result
        ((Total_vulc++))
    fi
}

U_16(){
    perm=$(( $(stat -c "%a" /etc/passwd) % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" /etc/passwd)
    group=$(stat -c "%g" /etc/passwd)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -gt 6 ] || [ "$perm_group" -gt 4 ] || [ "$perm_other" -gt 4 ]  ; then
        echo "U-16 취약: /etc/passwd 파일의 소유자가 root가 아니거나, 권한이 부적절하거나, 권한이 644 초과 (perm=$perm)" >> $result 
        ((Total_vulc++))
    fi


}

U_17(){
    mapfile -t stats < <(stat -c "%A %U %G %n" $(readlink -f /etc/rc*.d/* 2>/dev/null) 2>/dev/null)

    for stat in "${stats[@]}"; do
        perm=$(echo "$stat" | awk '{print $1}')
        owner=$(echo "$stat" | awk '{print $2}')
        file=$(echo "$stat" | awk '{print $4}')

        if [ "$owner" != "root" ]; then
            echo "U-17 취약: $file 파일의 소유자가 root가 아님 (owner=$owner)" >> $result
            ((Total_vulc++))

        elif echo "$perm" | grep -qE '^.{8}w'; then
            echo "U-17 취약: $file 파일에 일반 사용자(other) 쓰기 권한이 설정됨 (perm=$perm)" >> $result
            ((Total_vulc++))
        fi
    done

}

U_18(){
    perm=$(( $(stat -c "%a" /etc/shadow) % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" /etc/shadow)
    group=$(stat -c "%g" /etc/shadow)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -gt 4 ] || [ "$perm_group" -gt 0 ] || [ "$perm_other" -gt 0 ] ; then
        echo "U-18 취약: /etc/shadow 파일의 소유자가 root가 아니거나, group,other에 권한이 설정되어 있음 (perm=$perm)" >> $result 
        ((Total_vulc++))
    fi
}

U_19(){
    perm=$(( $(stat -c "%a" /etc/hosts) % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" /etc/hosts)
    group=$(stat -c "%g" /etc/hosts)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -gt 6 ] || [ "$perm_group" -gt 4 ] || [ "$perm_other" -gt 4 ] ; then
        echo "U-19 취약: /etc/hosts 파일의 소유자가 root가 아니거나, 권한이 644 초과 (perm=$perm)" >> $result 
        ((Total_vulc++))
    fi
}

U_20(){
    if [ -f /etc/inetd.conf ]; then
        inetconf=/etc/inetd.conf
    elif [ -f /etc/xinetd.conf ]; then
        inetconf=/etc/xinetd.conf
    else
        echo "U-20 검토 : /etc/inetd.conf 또는 /etc/xinetd.conf가 존재하지 않음" >> $result
        ((Rev++))
        return
    fi

    perm=$(( $(stat -c "%a" $inetconf) % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" $inetconf)
    group=$(stat -c "%g" $inetconf)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -gt 6 ] || [ "$perm_group" -gt 0 ] || [ "$perm_other" -gt 0 ] ; then
        echo "U-20 취약: $inetconf 파일의 소유자가 root가 아니거나, group,other에 권한이 설정되어 있음 (perm=$perm)" >> $result 
        ((Total_vulc++))
    fi

}

U_21(){
    if [ -f /etc/syslog.conf ]; then
        logconf=/etc/syslog.conf
    elif [ -f /etc/rsyslog.conf ]; then
        logconf=/etc/rsyslog.conf
    else
        echo "U-21 검토 : syslog/rsyslog 설정 파일이 존재하지 않음" >> "$result"
        ((Rev++))
        return
    fi

    perm=$(( $(stat -c "%a" "$logconf") % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" "$logconf")
    group=$(stat -c "%g" "$logconf")
    if [ "$owner" -ne 0 ] || [ "$group" -ne 0 ] || [ "$perm_owner" -gt 6 ] || [ "$perm_group" -gt 4 ] || [ "$perm_other" -gt 0 ] ; then
        echo "U-21 취약: $logconf 소유자/그룹이 root가 아니거나 권한이 640 초과 (perm=$perm)" >> "$result"
        ((Total_vulc++))
    fi
}

U_22(){
    perm=$(( $(stat -c "%a" /etc/services) % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" /etc/services)
    group=$(stat -c "%g" /etc/services)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -gt 6 ] || [ "$perm_group" -gt 4 ] || [ "$perm_other" -gt 4 ] ; then
        echo "U-22 취약: /etc/services 파일의 소유자가 root가 아니거나, 권한이 644 초과 (perm=$perm)" >> $result 
        ((Total_vulc++))
    fi
}

U_23(){
    executables=("/sbin/dump" "/sbin/restore" "/sbin/unix_chkpwd" "/usr/bin/at" "/usr/bin/lpq" "/usr/bin/lpq-lpd" "/usr/bin/lpr" "/usr/bin/lpr-lpd" "/usr/bin/lprm" "/usr/bin/lprm-lpd" "/usr/bin/newgrp" "/usr/sbin/lpc" "/usr/sbin/lpc-lpd" "/usr/sbin/traceroute")
    found=0
    for exe in "${executables[@]}"; do
        [ -e "$exe" ] || continue   # 파일이 없으면 건너뜀(우분투/패키지별로 흔함)

        found=1
        perm=$(stat -c '%A' -- "$exe" 2>/dev/null) || continue
        u=${perm:3:1}  # owner execute 자리
        g=${perm:6:1}  # group execute 자리

        if [[ "$u" =~ [sS] || "$g" =~ [sS] ]]; then
            echo "U-23 취약: $exe 파일에 SUID/SGID 설정($perm)" >> "$result"
            ((Total_vulc++))
        fi
    done

    if [ "$found" -eq 0 ]; then
        echo "U-23 검토: 점검 대상 주요 실행파일이 시스템에 존재하지 않음(패키지 미설치/경로 상이 가능)" >> "$result"
        ((Rev++))
    fi
}


U_24(){
    envfiles=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login")
    mapfile -t rows < <(
    awk -F: '$6!="" && $7 !~ /(\/false$|\/nologin$)/ {print $1 ":" $6}' /etc/passwd
    )

    users=()
    homes=()

    for row in "${rows[@]}"; do
    users+=( "${row%%:*}" )
    homes+=( "${row#*:}" )
    done
    for ((i=0; i<${#users[@]}; i++))
    do
        user=${users[$i]}
        home=${homes[$i]}
        if [ -d "$home" ]; then
            for ((j=0; j<${#envfiles[@]}; j++))
            do
                owner=$(stat -c %U ${home}/${envfiles[$j]} 2>/dev/null) || continue
                if [ "$owner" == "$user" ] || [ "$owner" == "root" ]; then
                    perm=$(stat -c "%a" ${home}/${envfiles[$j]})
                    perm_group=$((perm / 10 % 10))
                    perm_other=$((perm % 10))   
                    if [ "$perm_group" -eq 2 ] || [ "$perm_other" -eq 2 ] || [ "$perm_group" -eq 3 ] || [ "$perm_other" -eq 3 ] || [ "$perm_group" -ge 6 ] ||[ "$perm_other" -ge 6 ]; then
                        echo "U-24 취약: ${home}/${envfiles[$j]}에 group,other에 쓰기 권한이 설정되어 있음" >> $result 
                        ((Total_vulc++))
                    fi
                else
                    echo "U-24 취약  ${home}/${envfiles[$j]}의 소유자가 root나 해당 계정이 아님" >> $result 
                    ((Total_vulc++))
                fi
            done
        fi
    done
}

U_25(){
    mapfile -t WorldWritables < <(find /etc /bin /sbin /usr/bin /usr/sbin /lib /lib64 -type f -perm -2)
    for row in "${WorldWritables[@]}"; do
        if [[ $row =~ .conf ]]; then
            echo "U-25 취약 $row 파일이 설정 파일로 확인되고 다른 사용자의 쓰기 권한이 설정되어 있음" >> $result
            ((Total_vulc++))
        
        elif [ -x "$row" ]; then
            echo "U-25 취약 $row 파일이 실행 가능 파일로 확인되고 다른 사용자의 쓰기 권한이 설정되어 있음" >> $result
            ((Total_vulc++))
        else
            echo "U-25 검토: $row 파일에 다른 사용자의 쓰기 권한이 설정되어 있음" >> $result
            ((Rev++))
        fi

    done
}

U_26(){
	if [ `find /dev -type f 2>/dev/null | wc -l` -gt 0 ]; then
		echo "※ U-16 취약 : /dev 디렉터리에 존재하는 device 파일이 존재함." >> $result
        echo -e "파일 목록 \n`find /dev -type f -exec ls -l {} \; | awk '{print $9}' `" >> $result
        ((Total_vulc++))
	fi
}

U_27(){
    mapfile -t rows < <(
    awk -F: '{print $1 ":" $6}' /etc/passwd
    )
    vulc=0
    if [ -f /etc/hosts.equiv ]; then
        perm=$(( $(stat -c "%a" /etc/hosts.equiv) % 1000 ))
        perm_owner=$((perm / 100))
        perm_group=$((perm / 10 % 10))
        perm_other=$((perm % 10))
        owner=$(stat -c "%u" /etc/hosts.equiv)
        group=$(stat -c "%g" /etc/hosts.equiv)
        if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -gt 6 ] || [ "$perm_group" -gt 4 ] || [ "$perm_other" -gt 4 ] ; then
            echo "U-27 취약: /etc/hosts.equiv 파일의 소유자가 root가 아니거나, 권한이 644 초과 (perm=$perm)" >> $result 
            ((vulc++))
        fi
    fi

    users=()
    homes=()
    for row in "${rows[@]}"; do
    users+=( "${row%%:*}" )
    homes+=( "${row#*:}" )
    done
    for i in ${!homes[@]}; do
        if [ -d "${homes[$i]}" ]; then
            rhosts_plus_count=`grep -vE '^#|^\s#' ${homes[$i]}/.rhosts | grep '+' | wc -l`
            if [ $rhosts_plus_count -gt 0 ]; then
                echo "U-27 취약: ${homes[$i]}/.rhost 파일에 + 설정이 존재함" >> $result
                ((vulc++))
            fi

            if
                perm=$( $(stat -c "%a" "${homes[$i]}/.rhosts)" % 1000 ))
                perm_owner=$((perm / 100))
                perm_group=$((perm / 10 % 10))
                perm_other=$((perm % 10))
                owner=$(stat -c "%u" ${homes[$i]}/.rhosts)
                if [ $owner -ne "${users[$i]}" ] || [ "$perm_owner" -gt 6 ] || [ "$perm_group" -gt 0 ] || [ "$perm_other" -gt 0 ] ; then
                    echo "U-27 취약: ${homes[$i]}/.rhost  파일의 소유자가 해당 계정이 아니거나, 권한이 600 초과 (perm=$perm)" >> $result 
                    ((vulc++))
                fi
            fi
        fi
    done


    if [ $vulc -gt 0 ]; then
        ((Total_vulc++))
    fi
}

U_28(){
    echo "U-28 이 취약점에 대해서는 TCP Wrapper을 통해 적용한 접근제한 정책만을 진단하였음" >> $result
    vulc=0
    TCP_Wrapper_service=("systat" "in.fingerd" "vsftpd" "in.telnetd" "in.rlogind" "in.rshd" "in.talkd" "in.rexecd" "in.tftpd" "sshd") #TCP Wrapper로 제어하는 서비스에 따라 배열을 추가,제거할 것
    if [ -f /etc/hosts.deny ]; then
        if grep -vE '^[[:space:]]*#' /etc/host.deny | grep -iE  'all[[:space:]]*:[[:space:]]*all'; then
            if [ -f /etc/hosts.allow ]; then
                for service in "${TCP_Wrapper_service[@]}"; do
                    if grep -vE '^[[:space:]]*#' /etc/host.deny | grep -iE  '${service}[[:space:]]*:[[:space:]]*all'; then
                        echo "U-28 취약: /etc/host.allow의 ${service} 서비스에 대해 접근제한이 해제되어있음" >> $result
                        ((vulc++))                        
                    elif ! grep -vE '^[[:space:]]*#' /etc/host.deny | grep -iE  '${service}[[:space:]]*:'; then
                        echo "U-28 취약: /etc/host.allow에 ${service}에 대한 접근제한 설정이 존재하지 않음" >> $result
                        ((vulc++))
                    fi
                done
            else
                echo "U-28 검토: /etc/hosts.allow가 존재하지 않음" >> $result
                ((Rev++))
            fi
                
        else
            echo "U-28 취약: /etc/host.deny에 적절한 접근제한 설정이 존재하지 않음(ALL:ALL)" >> $result
            ((Total_vulc++))
        fi
    
    else 
        echo "U-28 검토: /etc/hosts.deny가 존재하지 않음" >> $result
        ((Rev++))
    fi

    if [ $vulc -gt 0 ]; then
        ((Total_vulc++))
    fi
    
}
    
U_29(){
    if ! [ -f /etc/host.lpd ]; then
        return
    else
        perm=$(( $(stat -c "%a" /etc/host.lpd) % 1000 ))
        perm_owner=$((perm / 100))
        perm_group=$((perm / 10 % 10))
        perm_other=$((perm % 10))
        owner=$(stat -c "%u" /etc/host.lpd)
        group=$(stat -c "%g" /etc/host.lpd)
        if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -gt 6 ] || [ "$perm_group" -gt 0 ] || [ "$perm_other" -gt 0 ] ; then
            echo "U-18 취약: /etc/host.lpd 파일이 존재하며 소유자가 root가 아니거나, group,other에 권한이 설정되어 있음 (perm=$perm)" >> $result 
            ((Total_vulc++))
        fi
    fi
}

U_30(){
    if [ -f /etc/profile ]; then
        umask=$(grep -vE '^[[:space:]]*#' /etc/profile | grep 'umask' | awk '{print $2}')
        if [ ${umask:2:1} -lt 2 ]; then
            echo "※ U-30 취약: 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않음" >> $result
            return 0
        elif [ ${umask:3:1} -lt 2 ]; then
            echo "※ U-30 취약: 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않음" >> $result
            ((Total_vulc++))
            return 0
        fi
    fi
    
    if [ -f /etc/login.defs ]; then
        umask=$(grep -E '^[[:space:]]*UMASK([[:space:]]+|=)' /etc/login.defs | awk -F '[=[:space:]]+' '{print $2}'| tr -d '[:space:]'| head -n 1)
        if [ ${umask:2:1} -lt 2 ]; then
            echo "※ U-30 취약: 그룹 사용자(group)에 대한 umask 값이 2 이상으로 설정되지 않음" >> $result
            return 0
        elif [ ${umask:3:1} -lt 2 ]; then
            echo "※ U-30 취약: 다른 사용자(other)에 대한 umask 값이 2 이상으로 설정되지 않음" >> $result
            ((Total_vulc++))
            return 0
        fi
    fi    

}

U_31(){
    mapfile -t rows < <(awk -F: '{print $1 ":" $6}' /etc/passwd)
    users=()
    homes=()

    for row in "${rows[@]}"; do
    users+=( "${row%%:*}" )
    homes+=( "${row#*:}" )
    done
    for i in ${!homes[@]}; do
        if [ -d "${homes[$i]}" ]; then
            home_owner=$(ls -ld ${homes[$i]}| awk '{print $2}')
            home_perm=$(ls -ld ${homes[$i]}| awk '{print $1}')
            if [ "$home_owner" != "${users[$i]}" ]; then
                echo "U-31 취약: ${users[$i]} 홈 디렉터리의 소유자가 해당 계정이 아님 ${homes[$i]}" >> $result
                ((Total_vulc++))
            fi
            if [ "${home_perm:8:1}" == "w" ];then
                echo "U-31 취약: ${users[$i]} 홈 디렉터리에 다른 사용자에 대한 쓰기 권한이 설정되어 있음 ${homes[$i]}" >> $result
                ((Total_vulc++))
            fi
        
        else 
            echo "U-31 검토: ${homes[$i]} 디렉터리가 존재하지 않음" >> $result
            ((Rev++))
        fi
    done
}


U_32(){
    mapfile -t rows < <(awk -F: '$7 !~ /(nologin|false)$/ {print $1 ":" $6}' /etc/passwd)
    users=()
    homes=()
    vulc=0
    for row in "${rows[@]}"; do
    users+=( "${row%%:*}" )
    homes+=( "${row#*:}" )
    done

    for i in "${!homes[@]}"; do
        if [ ! -d "${homes[$i]}" ]; then
            echo "U-32 취약: ${users[$i]}의 홈 디렉터리가 존재하지 않음" >> $result
            ((vulc++))
        fi
    done

    if [ $vulc -gt 0 ]; then
        ((Total_vulc++))
    fi

}

U_33(){
    hidden="hiddenlist.txt"
    hiddenfile=$(find / -name '.*' -type f 2>/dev/null)
    hiddendir=$(find / -name '.*' -type d 2>/dev/null)

	if [ -n "$hiddenfile" ]; then
        echo "U-33 검토: 숨겨진 파일이 존재함 hiddenlist.txt 참고" >> $result
        echo "file list" >>$hidden
        echo >> "$hidden" 
        echo "${hiddenfile}" >> $hidden
        ((Rev++))
    fi

    if [ -n "$hiddendir" ]; then
        echo "U-33 검토: 숨겨진 디렉터리가 존재함 hiddenlist.txt 참고" >> $result
        echo "dir list" >>$hidden
        echo >> "$hidden" 
        echo "${hiddendir}" >> $hidden
        ((Rev++))
    fi
}

U_34(){
    if ! dpkg -l | grep -q finger; then
        return 0
    fi

    if [ -f /etc/inetd.conf ]; then
        if grep -vE '^[[:space:]]*#' /etc/inetd.conf | grep -q finger; then
            echo "U-34 취약: finger 서비스가 설치되어있고 /etc/inetd.conf에 활성화되도록 설정되어 있음" >> $result
            ((Total_vulc++))
        fi
    elif [ -d /etc/xinetd.d ]; then
        finger=$(grep -l '^[[:space:]]*service[[:space:]]\+finger' /etc/xinetd.d/* 2>/dev/null | head -n 1)

        if [ -n "$finger" ]; then
            if ! grep -qi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$finger"; then
                echo "U-34 취약: finger 서비스가 설치되어 있고 xinetd에서 활성화 상태임 ($finger)" >> $result
                ((Total_vulc++))
            fi
        fi

    else 

    if systemctl list-unit-files 2>/dev/null | grep -q finger; then
        echo "U-34 검토: inetd xinet가 없으나 finger 서비스 존재" >> $result
        ((Rev++))
    fi

    fi
}


U_35(){
    vulc=0

    #기본 FTP
    if grep -q 'ftp' /etc/passwd; then
        echo "U-35 취약: ftp 계정이 존재함." >> $result
        ((vulc++))
        
    fi
    if grep -q 'anonymous' /etc/passwd; then
        echo "U-35 취약: anonymous 계정이 계정이 존재함." >> $result
        ((vulc++))
    fi

    #vsFTP
    if [ -f /etc/vsftpd.conf ]; then
        if grep -vE '^[[:space:]]*#' /etc/vsftpd.conf | grep -qi '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*yes'; then
            echo "U-35 취약: vsFTP에서 anonymous_enable이 설정되어 있음." >> $result
            ((vulc++))
        fi  
    elif [ -f /etc/vsftpd/vsftpd.conf ]; then
        if grep -vE '^[[:space:]]*#' /etc/vsftpd/vsftpd.conf | grep -qi '^[[:space:]]*anonymous_enable[[:space:]]*=[[:space:]]*yes'; then
            echo "U-35 취약: vsFTP에서 anonymous_enable이 설정되어 있음." >> $result
            ((vulc++))
        fi  
    fi

    #proFTPD
    if [ -f /etc/proftpd/proftpd.conf ]; then
        if sed -n '/<Anonymous ~ftp>/,/<\/Anonymous>/p' /etc/proftpd/proftpd.conf | grep -vE '^[[:space:]]*#'; then
            echo "U-35 취약: proFTPD에서 anonymous 설정이 존재함." >> $result
            ((vulc++))
        fi
    fi
    #NFS
    if [ -f /etc/dfs/dfstab ]; then
        if ! grep -vE '^[[:space:]]*#' /etc/dfs/dfstab | grep -qi '^[[:space:]]*share.*anon[[:space:]]*=[[:space:]]*-1'; then
            echo "U-35 취약: NFS에서 anonymous가 허용되어 있음." >> $result
            ((vulc++))
        fi
    fi
    #SAMBA
    if [ -f /etc/samba/smb.conf ]; then
        if grep -vE '^[[:space:]]*#' /etc/samba/smb.conf | grep -qi '^[[:space:]]*guest ok[[:space:]]*=[[:space:]]*yes'; then
            echo "U-35 취약: SAMBA에서 guest ok가 설정되어 있음." >> $result
            ((vulc++))
        fi
    fi

    if [ $vulc -gt 0 ]; then
        ((Total_vulc++))
    fi
}

U_36(){
    vulc=0
    if [ -f /etc/hosts.equiv ]; then
        echo "U-36 취약: /etc/hosts.equiv 파일이 존재함" >> $result
        ((vulc++))
    fi

    mapfile -t rows < <(awk -F: '{print $1 ":" $6}' /etc/passwd)
    users=()
    homes=()

    for row in "${rows[@]}"; do
    users+=( "${row%%:*}" )
    homes+=( "${row#*:}" )
    done

    for i in ${!homes[@]}; do
        if [ -d "${homes[$i]}" ]; then
            if [ -f "${homes[$i]}/.rhosts" ]; then
                echo "U-36 취약: ${users[$i]} 홈 디렉터리에 .rhosts 파일이 존재함" >> $result
                ((vulc++))
            fi
        fi
    done
    if [ -f /etc/inetd.conf ]; then
        if grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*shell[[:space:]]'; then
            echo "U-36 취약: /etc/inetd.conf 파일에서 shell 서비스가 활성화 되어있음" >> $result
            ((vulc++))
        fi
        if grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*login[[:space:]]'; then
            echo "U-36 취약: /etc/inetd.conf 파일에서 login 서비스가 활성화 되어있음" >> $result
            ((vulc++))
        fi
        if grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*exec[[:space:]]'; then
            echo "U-36 취약: /etc/inetd.conf 파일에서 exec 서비스가 활성화 되어있음" >> $result
            ((vulc++))
        fi
        
    elif [ -d /etc/xinetd.d ]; then
        shell=$(grep -l '^[[:space:]]*service[[:space:]]\+shell' /etc/xinetd.d/* 2>/dev/null | head -n 1)
        login=$(grep -l '^[[:space:]]*service[[:space:]]\+login' /etc/xinetd.d/* 2>/dev/null | head -n 1)
        exec=$(grep -l '^[[:space:]]*service[[:space:]]\+exec' /etc/xinetd.d/* 2>/dev/null | head -n 1)

        if [ -n "$shell" ]; then
            if ! grep -qi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$shell"; then
                echo "U-36 취약: shell 서비스가 xinetd에서 활성화 상태임 ($shell)" >> $result
                ((vulc++))
            fi
        fi

        if [ -n "$login" ]; then
            if ! grep -qi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$finger"; then
                echo "U-34 취약: login 서비스가 xinetd에서 활성화 상태임 ($login)" >> $result
                ((vulc++))
            fi
        fi

        if [ -n "$exec" ]; then
            if ! grep -qi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$exec"; then
                echo "U-36 취약: exec 서비스가 xinetd에서 활성화 상태임 ($exec)" >> $result
                ((vulc++))
            fi
        fi
    elif systemctl list-unit-files 2>/dev/null | grep -qE 'rsh|rlogin|rexec'; then
        echo "U-36 검토: inetd, xinetd가 없으나 shell,login,exec 서비스 존재" >> $result
        ((Rev++))
    fi

    if [ $vulc -gt 0 ]; then
        ((Total_vulc++))
    fi
}


U_37(){
    vulc=0
    if [ -f /usr/bin/crontab ]; then
        perm=$(( $(stat -c "%a" /usr/bin/crontab) % 1000 ))
        perm_owner=$((perm / 100))
        perm_group=$((perm / 10 % 10))
        perm_other=$((perm % 10))
        owner=$(stat -c "%u" /usr/bin/crontab)
        group=$(stat -c "%g" /usr/bin/crontab)
        if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_group" -gt 5 ] || [ "$perm_other" -gt 0 ] ; then
            echo "U-37 취약: /usr/bin/crontab 파일의 소유자가 root가 아니거나, 권한이 부적절하게 설정되어 있음 (perm=$perm)" >> $result 
            ((vulc++))
        fi
    fi

    if [ -f /usr/bin/at ]; then
        perm=$(( $(stat -c "%a" /usr/bin/at) % 1000 ))
        perm_owner=$((perm / 100))
        perm_group=$((perm / 10 % 10))
        perm_other=$((perm % 10))
        owner=$(stat -c "%u" /usr/bin/at)
        group=$(stat -c "%g" /usr/bin/at)
        if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_group" -gt 5 ] || [ "$perm_other" -gt 0 ] ; then
            echo "U-37 취약: /usr/bin/at 파일의 소유자가 root가 아니거나, 권한이 750을 넘음 (perm=$perm)" >> $result 
            ((vulc++))
        fi
    fi

    mapfile -t crons < <(find /var/spool/cron -type f -perm /037 2>/dev/null)
    mapfile -t ats < <(find /var/spool/at -type f -perm /037 2>/dev/null)
    mapfile -t etccrons < <(find /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.allow /etc/cron.deny -type f -perm /037 2>/dev/null)
    mapfile -t etcats < <(find /etc/at /etc/at.allow /etc/at.deny -type f -perm /037 2>/dev/null)
    for cron in "${crons[@]}"; do
        echo "U-37 취약: $cron 파일에 권한이 부적절하게 설정되어 있음 " >> $result
        ((vulc++))
    done
    for at in "${ats[@]}"; do
        echo "U-37 취약: $at 파일에 권한이 부적절하게 설정되어 있음" >> $result
        ((vulc++))
    done
    for etccron in "${etccrons[@]}"; do
        echo "U-37 취약: $etccron 파일에 권한이 부적절하게 설정되어 있음" >> $result
        ((vulc++))
    done

    for etcat in "${etcats[@]}"; do
        echo "U-37 취약: $etcat 파일에 권한이 부적절하게 설정되어 있음" >> $result
        ((vulc++))
    done

    if [ $vulc -gt 0 ]; then
        ((Total_vulc++))
    fi
}

U_38(){
    if [ -f /etc/inetd.conf ]; then
        if grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*echo[[:space:]]'; then
            echo "U-38 취약: /etc/inetd.conf 파일에서 echo 서비스가 활성화 되어있음" >> $result
            ((vulc++))
        fi

        if grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*discard[[:space:]]'; then
            echo "U-38 취약: /etc/inetd.conf 파일에서 discard 서비스가 활성화 되어있음" >> $result
            ((vulc++))
        fi

        if grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*daytime[[:space:]]'; then
            echo "U-38 취약: /etc/inetd.conf 파일에서 daytime 서비스가 활성화 되어있음" >> $result
            ((vulc++))
        fi

        if grep -vE '^[[:space:]]*#' /etc/inetd.conf 2>/dev/null | grep -qE '^[[:space:]]*chargen[[:space:]]'; then
            echo "U-38 취약: /etc/inetd.conf 파일에서 chargen 서비스가 활성화 되어있음" >> $result
            ((vulc++))
        fi
        
    elif [ -d /etc/xinetd.d ]; then
        echo=$(grep -l '^[[:space:]]*service[[:space:]]\+echo' /etc/xinetd.d/* 2>/dev/null | head -n 1)
        discard=$(grep -l '^[[:space:]]*service[[:space:]]\+discard' /etc/xinetd.d/* 2>/dev/null | head -n 1)
        daytime=$(grep -l '^[[:space:]]*service[[:space:]]\+daytime' /etc/xinetd.d/* 2>/dev/null | head -n 1)
        chargen=$(grep -l '^[[:space:]]*service[[:space:]]\+chargen' /etc/xinetd.d/* 2>/dev/null | head -n 1)

        if [ -n "$echo" ]; then
            if ! grep -qi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$echo"; then
                echo "U-38 취약: echo 서비스가 xinetd에서 활성화 상태임 ($echo)" >> $result
                ((vulc++))
            fi
        fi
        if [ -n "$discard" ]; then
            if ! grep -qi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$discard"; then
                echo "U-38 취약: discard 서비스가 xinetd에서 활성화 상태임 ($discard)" >> $result
                ((vulc++))
            fi
        fi
        if [ -n "$daytime" ]; then
            if ! grep -qi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$daytime"; then
                echo "U-38 취약: daytime 서비스가 xinetd에서 활성화 상태임 ($daytime)" >> $result
                ((vulc++))
            fi
        fi
        if [ -n "$chargen" ]; then
            if ! grep -qi '^[[:space:]]*disable[[:space:]]*=[[:space:]]*yes' "$chargen"; then
                echo "U-38 취약: chargen 서비스가 xinetd에서 활성화 상태임 ($chargen)" >> $result
                ((vulc++))
            fi
        fi
    elif systemctl list-unit-files 2>/dev/null | grep -qE 'echo|discard|daytime|chargen'; then
        echo "U-38 검토: inetd, xinetd가 없으나 echo,discard,daytime,chargen 서비스 존재" >> $result
        ((Rev++))
    fi
    if [ $vulc -gt 0 ]; then
        ((Total_vulc++))
    fi
}

U_39(){
    if systemctl list-units --type=service 2>/dev/null | grep -qE 'nfs'; then
        echo "U-39 취약: NFS 서비스 관련 데몬이 활성화 되어 있음" >> $result
        ((Total_vulc++))
    fi
}

U_40(){
    vulc=0
    if [ -f /etc/exports ]; then
        perm=$(( $(stat -c "%a" /etc/exports) % 1000 ))
        perm_owner=$((perm / 100))
        perm_group=$((perm / 10 % 10))
        perm_other=$((perm % 10))
        owner=$(stat -c "%u" /etc/exports)
        group=$(stat -c "%g" /etc/exports)
        if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -gt 6 ] || [ "$perm_group" -gt 4 ] || [ "$perm_other" -gt 4 ] ; then
            echo "U-40 취약: /etc/exports 파일의 소유자가 root가 아니거나, 권한이 644를 넘음 (perm=$perm)" >> $result 
            ((vulc++))
        fi

        not_allowed_count=$(grep -vE '^[[:space:]]*#' /etc/exports | grep -E '\(.*insecure.*\)|\*\(.*rw.*\)|\*\(.*ro.*\)|\(.*no_root_squash.*\)' | wc -l)
        if [ $not_allowed_count -gt 0 ]; then
            echo "U-40 취약: /etc/exports 파일에 보안상 부적절한 설정이 존재함" >> $result 
            ((vulc++))
        fi

    fi

    if [ $vulc -gt 0 ]; then
        ((Total_vulc++))
    fi
}