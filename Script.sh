result="result.txt"
#취약점 발견시 카운트 상승
Vulc=0

#U-01
U_01(){
    if [ -f /etc/ssh/sshd_config ]; then
        check=`grep -iE '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config | awk -F'[ =]+' '{print $2}'`
        if [ "$check" != "no" ]; then
            echo "U_01 sshd PermitRootLogin 허용 설정 발견" >> $result
            ((Vulc++))
        fi
    fi

    if [ -f /etc/securetty ]; then
        size= $(wc -c /etc/securetty | awk '{print $1}')
        if [ $size -ne 0 ]; then
            echo "U_01 /etc/securetty에 내용 존재" >> $result
            ((Vulc++))
        fi
    else
        echo "U_01 /etc/securetty가 존재하지 않아 로그인 차단 미적용" >> $result
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
                echo "U_02 취약:동일 패스워드 사용 불가 수준 미달 (difok)" >> $result
                ((Vulc++))
            fi

        # credit 계열
        else
            if [ "$check" -gt -1 ]; then
                echo "U_02 $param 값 이상 발견" >> $result
                ((Vulc++))
            fi
        fi
    done
}
U_03() {
    echo "----- U-03 계정 잠금 임계값 설정 점검 -----"

    if [ -f /etc/pam.d/common-auth ]; then
        if grep -Eq "pam_(tally2|faillock).*deny *= *[0-9]+" /etc/pam.d/common-auth; then
            echo "U-03 양호: 계정 잠금 임계값 설정(pam_tally2/pam_faillock deny 값 존재)" >> $result
            ((Vulc++))
        
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
