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
        size= $(wc -c /etc/securetty | awk '{print $1}')
        if [ $size -ne 0 ]; then
            echo "U_01 취약: /etc/securetty에 내용 존재" >> $result
            ((Vulc++))
        fi
    else
        echo "U_01 취약: /etc/securetty가 존재하지 않아 로그인 차단 미적용" >> $result
        ((Vulc++))

    fi
}
#U_02
U_02(){
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
}
U_03() {
    echo "----- U-03 계정 잠금 임계값 설정 점검 -----"

    if [ -f /etc/pam.d/common-auth ]; then
        if grep -Eq "pam_(tally2|faillock).*deny *= *[0-9]+" /etc/pam.d/common-auth; then
            #echo "U-03 양호: 계정 잠금 임계값 설정(pam_tally2/pam_faillock deny 값 존재)" >> $result
        
        elif grep -Eq "pam_(tally2|faillock).*deny" /etc/pam.d/common-auth; then
            echo "U-03 취약: deny 옵션은 있으나 유효한 숫자 값이 없음" >> $result
            ((Vulc++))
        else
            echo "U-03 취약: 계정 잠금 임계값(deny) 미설정" >> $result
            ((Vulc++))
        fi
    fi
}

U_04(){

    while IFS= read -r line
    do
        user=$(echo "$line" | awk -F ':' '{print $1}')
        pw=$(echo "$line" | awk -F ':' '{print $2}')
        if [[ ! "$pw" =~ ^\$[0-9A-Za-z]+\$.+ && "$pw" != "*" && "$pw" != "!" ]]; then
            echo "U-04 취약: shadow파일에 $user (pw='$pw')" >> $result
            ((Vulc++))
        fi
        
    done < /etc/shadow

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
    if [ `echo $PATH | grep -E '\.:|::' | wc -l` -gt 0 ]; then
        echo "U-05 취약: 환경변수 앞에 "." 이나 "::" 이 포함되어 있음" >> $result
        ((Vulc++))
    fi
}

U_06(){
    count=$(find / \( -nouser -or -nogroup \) 2>/dev/null | wc -l)
    if [ $count -ne 0 ]; then
        echo "U-06 취약: 소유자가 없거나 소유 그룹이 존재하지 않는 파일 발견" >> $result
        echo $(find / \( -nouser -or -nogroup \) 2>/dev/null) >> $result
        ((Vulc++))
    fi
}

U_07(){
    perm=$(( $(stat -c "%a" /etc/passwd) % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" /etc/passwd)
    group=$(stat -c "%g" /etc/passwd)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -le 6 ] || [ "$perm_group" -ge 2 ] || [ "$perm_other" -ge 2 ] ; then
        echo "U-07 취약: /etc/passwd 파일의 소유자가 root가 아니거나, 권한이 부적절하거나, group,other에 쓰기 권한이 설정되어 있음" >> $result 
        ((Vulc++))
    fi
}

U_08(){
    perm=$(( $(stat -c "%a" /etc/shadow) % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" /etc/shadow)
    group=$(stat -c "%g" /etc/shadow)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -le 4 ] || [ "$perm_group" -ne 0 ] || [ "$perm_other" -ne 0 ] ; then
        echo "U-08 취약: /etc/shadow 파일의 소유자가 root가 아니거나, group,other에 권한이 설정되어 있음" >> $result 
        ((Vulc++))
    fi
}

U_09(){
    perm=$(( $(stat -c "%a" /etc/hosts) % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" /etc/hosts)
    group=$(stat -c "%g" /etc/hosts)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -le 6 ] || [ "$perm_group" -ne 0 ] || [ "$perm_other" -ne 0 ] ; then
        echo "U-09 취약: /etc/hosts 파일의 소유자가 root가 아니거나, group,other에 권한이 설정되어 있음" >> $result 
        ((Vulc++))
    fi
}

U_10(){
    if [ -f /etc/inetd.conf ]; then
        inetconf=/etc/inetd.conf
    elif [ -f /etc/xinetd.conf ]; then
        inetconf=/etc/xinetd.conf
    else
        echo "U-10 검토 : /etc/inetd.conf 또는 /etc/xinetd.conf가 존재하지 않음" >> $result
        ((Rev++))
        return
    fi

    perm=$(( $(stat -c "%a" $inetconf) % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" $inetconf)
    group=$(stat -c "%g" $inetconf)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -le 6 ] || [ "$perm_group" -ne 0 ] || [ "$perm_other" -ne 0 ] ; then
        echo "U-10 취약: $inetconf 파일의 소유자가 root가 아니거나, group,other에 권한이 설정되어 있음" >> $result 
        ((Vulc++))
    fi

}

U_11(){
    perm=$(( $(stat -c "%a" /etc/syslog.conf) % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" /etc/syslog.conf)
    group=$(stat -c "%g" /etc/syslog.conf)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -le 6 ] || [ "$perm_group" -ge 2 ] || [ "$perm_other" -ne 0 ] ; then
        echo "U-11 취약: /etc/syslog.conf 파일의 소유자가 root가 아니거나, group,other에 권한이 설정되어 있음" >> $result 
        ((Vulc++))
    fi
}

U_12(){
    perm=$(( $(stat -c "%a" /etc/services) % 1000 ))
    perm_owner=$((perm / 100))
    perm_group=$((perm / 10 % 10))
    perm_other=$((perm % 10))
    owner=$(stat -c "%u" /etc/services)
    group=$(stat -c "%g" /etc/services)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm_owner" -le 6 ] || [ "$perm_group" -ge 2 ] || [ "$perm_other" -ge 2 ] ; then
        echo "U-07 취약: /etc/services 파일의 소유자가 root가 아니거나, 권한이 부적절하거나, group,other에 쓰기 권한이 설정되어 있음" >> $result 
        ((Vulc++))
    fi
}

U_13(){
    executables=("/sbin/dump" "/sbin/restore" "/sbin/unix_chkpwd" "/usr/bin/at" "/usr/bin/lpq" "/usr/bin/lpq-lpd" "/usr/bin/lpr" "/usr/bin/lpr-lpd" "/usr/bin/lprm" "/usr/bin/lprm-lpd" "/usr/bin/newgrp" "/usr/sbin/lpc" "/usr/sbin/lpc-lpd" "/usr/sbin/traceroute")
	for ((i=0; i<${#executables[@]}; i++))
	do
        if [ -f ${executables[$i]} ]; then
            if ls -alL ${executables[$i]} | awk '{ print $1}' | grep -i 's'; then
                echo "U-13 취약: ${executables[$i]} 파일에 SUID 또는 SGID가 설정되어 있음" >> $result
                ((Vulc++))
            fi
        fi
	done
}