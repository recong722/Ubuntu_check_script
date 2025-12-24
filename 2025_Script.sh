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

U_16(){
    perm=$(stat -c "%a" /etc/passwd)
    owner=$(stat -c "%u" /etc/passwd)
    group=$(stat -c "%g" /etc/passwd)
    if [ $owner -ne 0 ] || [ $group -ne 0 ] || [ "$perm" -gt 644 ] ; then
        echo "U-16 취약: /etc/passwd 파일의 소유자가 root가 아니거나, 권한이 부적절하거나, 권한이 644 초과 (perm=$perm)" >> $result 
        ((Vulc++))
    fi
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

