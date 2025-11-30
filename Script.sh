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
            echo "U_02 $param 미설정"
            ((Vulc++))
            continue
        fi

        # minlen 검사
        if [ "$param" = "minlen"  ]; then
            if [ "$check" -lt 8 ]; then
                echo "U_02 최소 패스워드 길이 부족"
                ((Vulc++))
            fi

        # difok 비어 있는 경우 취약
        elif [ "$param" = "difok"  ]; then
            if [ "$check" -lt 1 ]; then
                echo "U_02 동일 패스워드 사용 불가 수준 미달 (difok)"
                ((Vulc++))
            fi

        # credit 계열
        else
            if [ "$check" -gt -1 ]; then
                echo "U_02 $param 값 이상 발견"
                ((Vulc++))
            fi
        fi
    done
}