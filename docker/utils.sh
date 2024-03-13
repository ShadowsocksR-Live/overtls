#!/bin/bash
echolog() {
    echo -e "\033[32m[overtls log]\033[0m" $*
}

echoerr() {
    echo -e "\033[31m[overtls err]\033[0m" $*
}

random_string_gen() {
    local PASS=""
    local MATRIX="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" # "~!@#$%^&*()_+="
    local LENGTH=$1
    [ -z $1 ] && LENGTH="16"
    while [ "${n:=1}" -le "$LENGTH" ]
    do
        PASS="$PASS${MATRIX:$(($RANDOM%${#MATRIX})):1}"
        let n+=1
    done

    echo ${PASS}
}

gettunnelpath(){
    TUNNEL_PATH_STRING="$TUNNEL_PATH"   
    TUNNEL_PATH_STRING="${TUNNEL_PATH_STRING#,}"  
    TUNNEL_PATH_STRING="${TUNNEL_PATH_STRING%,}"  
    NEW_TUNNEL_PATH=""  
    OLD_IFS="$IFS"
    IFS=','  
    for item in $TUNNEL_PATH_STRING; do  
        item="${item#"${item%%[![:space:]]*}"}"  
        item="${item%"${item##*[![:space:]]}"}" 
        if [ -n "$NEW_TUNNEL_PATH" ]; then  
            NEW_TUNNEL_PATH="$NEW_TUNNEL_PATH,\"$item\""  
        else  
            NEW_TUNNEL_PATH="\"$item\""  
        fi  
    done  
    IFS="$OLD_IFS"
    NEW_TUNNEL_PATH="[${NEW_TUNNEL_PATH}]"  
    echo $NEW_TUNNEL_PATH
}