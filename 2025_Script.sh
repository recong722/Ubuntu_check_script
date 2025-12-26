result="result.txt"
#취약점 발견시 카운트 상승
Vulc=0
Rev=0
#U-01
U_01(){
    if [ -f /etc/ssh/sshd_config ]; then
        check=`grep -iE '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config | awk -F'[ =]+' '{print $2}'`
        if [ "$check" != "no" ]; then
            echo "U_01 취약: sshd PermitRootLogin 허용 설정 발견" >> $result
            ((Vulc++))
        fi
    fi

    if [ -f /etc/securetty ]; then
        size=$(wc -c /etc/securetty | awk '{print $1}')
        if [ $size -ne 0 ]; then
            echo "U_01 취약: /etc/securetty에 내용 존재" >> $result
            ((Vulc++))
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
                ((Vulc++))
                continue
            fi

            # minlen 검사
            if [ "$param" = "minlen"  ]; then
                if [ "$check" -lt 8 ]; then
                    echo "U_02 취약: 최소 패스워드 길이 부족" >> $result
                    ((Vulc++))
                fi

            # difok 비어 있는 경우 취약
            elif [ "$param" = "difok"  ]; then
                if [ "$check" -lt 1 ]; then
                    echo "U_02 취약: 동일 패스워드 사용 불가 수준 미달 (difok)" >> $result
                    ((Vulc++))
                fi

            # credit 계열
            else
                if [ "$check" -gt -1 ]; then
                    echo "U_02 취약: $param 값 이상 발견" >> $result
                    ((Vulc++))
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
                ((Vulc++))
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
            ((Vulc++))
        fi
        
    done < /etc/passwd
}

U_05(){
    InvalidUser=$(awk -F : '$3 == 0 && $1 != "root" {print $1}' /etc/passwd )
    if [ -z "$InvalidUser" ]; then
        echo "U-05 취약 : root를 제외하고 uid가 0인 계정 존재 /etc/passwd" >> $result
        ((Vulc++))
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
            ((Vulc++))
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
        ((Vulc++))
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
    ((Vulc++))
}

U_11(){
    noneeds=("daemon" "bin" "sys" "adm" "listen" "nobody" "nobody4" "noaccess" "diag" "operator" "games" "gopher")
    for noneed in "${noneeds[@]}"; do
        check=$(awk -F : '$1==$noneed {print $7}' /etc/passwd)
        if [ "$check"!="/bin/false" ] && [ "$check"!="/sbin/nologin" ]; then
            echo "U-11 취약: 로그인이 필요하지않은 계정에 /bin/false 혹은 /sbin/nologin이 부여되어 있지 않음 ($noneed)" >> $result
            ((Vulc++))
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
        ((Vulc++))
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
        ((Vulc++))
    fi
    if ! grep -vE '^[[:space:]]*#' /etc/pam.d/common-password 2>/dev/null | grep 'pam_unix.so' | grep -Eq 'sha512|sha256|yescrypt'; then
        echo "U-13 취약: /etc/pam.d/common-password에 암호화 알고리즘 설정이 부적절함" >> $result
        ((Vulc++))
    fi

}

U_14(){
    if echo "$PATH" | grep -Eq '(^|:)\.(\:|$)|::'; then
        echo "U-14 취약: PATH에 현재 디렉터리(.) 또는 빈 경로(::)가 포함되어 있음" >> "$result"
        ((Vulc++))
    fi
}

U_15(){
    count=$(find / \( -nouser -or -nogroup \) 2>/dev/null | wc -l)
    if [ $count -ne 0 ]; then
        echo "U-06 취약: 소유자가 없거나 소유 그룹이 존재하지 않는 파일 발견" >> $result
        echo $(find / \( -nouser -or -nogroup \) 2>/dev/null) >> $result
        ((Vulc++))
    fi
}

U_16(){
    perm=$(stat -c "%a" /etc/passwd)
    owner=$(stat -c "%u" /etc/passwd)
    group=$(stat -c "%g" /etc/passwd)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm" -gt 644 ] ; then
        echo "U-16 취약: /etc/passwd 파일의 소유자가 root가 아니거나, 권한이 부적절하거나, 권한이 644 초과 (perm=$perm)" >> $result 
        ((Vulc++))
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
            ((Vulc++))

        elif echo "$perm" | grep -qE '^.{8}w'; then
            echo "U-17 취약: $file 파일에 일반 사용자(other) 쓰기 권한이 설정됨 (perm=$perm)" >> $result
            ((Vulc++))
        fi
    done

}

U_18(){
    perm=$(stat -c "%a" /etc/shadow)
    owner=$(stat -c "%u" /etc/shadow)
    group=$(stat -c "%g" /etc/shadow)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm" -gt 400 ] ; then
        echo "U-18 취약: /etc/shadow 파일의 소유자가 root가 아니거나, group,other에 권한이 설정되어 있음 (perm=$perm)" >> $result 
        ((Vulc++))
    fi
}

U_19(){
    perm=$(stat -c "%a" /etc/hosts)
    owner=$(stat -c "%u" /etc/hosts)
    group=$(stat -c "%g" /etc/hosts)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm" -gt 644 ] ; then
        echo "U-19 취약: /etc/hosts 파일의 소유자가 root가 아니거나, 권한이 644 초과 (perm=$perm)" >> $result 
        ((Vulc++))
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

    perm=$(stat -c "%a" $inetconf)
    owner=$(stat -c "%u" $inetconf)
    group=$(stat -c "%g" $inetconf)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm" -gt 600 ] ; then
        echo "U-20 취약: $inetconf 파일의 소유자가 root가 아니거나, group,other에 권한이 설정되어 있음 (perm=$perm)" >> $result 
        ((Vulc++))
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

    perm=$(stat -c "%a" "$logconf")
    owner=$(stat -c "%u" "$logconf")
    group=$(stat -c "%g" "$logconf")
    if [ "$owner" -ne 0 ] || [ "$group" -ne 0 ] || [ "$perm" -gt 640 ] ; then
        echo "U-21 취약: $logconf 소유자/그룹이 root가 아니거나 권한이 640 초과 (perm=$perm)" >> "$result"
        ((Vulc++))
    fi
}

U_22(){
    perm=$(stat -c "%a" /etc/services)
    owner=$(stat -c "%u" /etc/services)
    group=$(stat -c "%g" /etc/services)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm" -gt 644 ] ; then
        echo "U-22 취약: /etc/services 파일의 소유자가 root가 아니거나, 권한이 644 초과 (perm=$perm)" >> $result 
        ((Vulc++))
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
            ((Vulc++))
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
                        ((Vulc++))
                    fi
                else
                    echo "U-24 취약  ${home}/${envfiles[$j]}의 소유자가 root나 해당 계정이 아님" >> $result 
                    ((Vulc++))
                fi
            done
        fi
    done
}

