#!/bin/sh
# Один установщик: монитор или агент. Комплект — этот скрипт и два бинарника рядом,
# службы systemd он пишет сам. Без бинарника рядом агент качается с монитора.
# Тело — только функции, вызов в последней строке: оборванная загрузка через curl | sh ничего не выполнит.

die() { printf '%s\n' "$1" >&2; exit "${2:-1}"; }

nm_arch() {
    case "$(uname -m)" in
        x86_64) printf amd64 ;;
        aarch64|arm64) printf arm64 ;;
        *) die "Нужны amd64 или arm64" 2 ;;
    esac
}

nm_ask() {
    # $1 подпись, $2 значение по умолчанию
    if [ -n "$2" ]; then
        printf '%s [Enter = %s]: ' "$1" "$2" >&2
    else
        printf '%s: ' "$1" >&2
    fi
    IFS= read -r nm_ans || nm_ans=
    if [ -z "$nm_ans" ]; then nm_ans=$2; fi
    printf '%s' "$nm_ans"
}

nm_secret() {
    printf '%s: ' "$1" >&2
    if [ -t 0 ]; then stty -echo; fi
    IFS= read -r nm_ans || nm_ans=
    if [ -t 0 ]; then stty echo; printf '\n' >&2; fi
    printf '%s' "$nm_ans"
}

nm_yes() {
    # $2 — ответ на Enter: y (по умолчанию) или n. Непонятный ответ — вопрос ещё раз.
    nm_yes_def=${2:-y}
    while true; do
        printf '%s [y — да, n — нет, Enter = %s]: ' "$1" "$nm_yes_def" >&2
        IFS= read -r nm_ans || nm_ans=
        [ -n "$nm_ans" ] || nm_ans=$nm_yes_def
        case "$nm_ans" in
            y|Y|yes|YES|Yes|д|Д|да|Да|ДА) return 0 ;;
            n|N|no|NO|No|н|Н|нет|Нет|НЕТ) return 1 ;;
        esac
        printf 'Ответь y или n.\n' >&2
    done
}

nm_port_busy() {
    ss -ltn 2>/dev/null | awk -v p="$1" '
        $4 ~ /:/ {
            n = $4
            sub(/.*:/, "", n)
            if (n == p) found = 1
        }
        END { exit found ? 0 : 1 }
    '
}

nm_suggest_port() {
    nm_p=8443
    while nm_port_busy "$nm_p"; do
        nm_p=$((nm_p + 1))
        [ "$nm_p" -le 65535 ] || die "Свободного порта нет"
    done
    printf '%s' "$nm_p"
}

nm_default_ip() {
    ip -4 route get 1.1.1.1 2>/dev/null | awk '{
        for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }
    }'
}

nm_ensure_pkgs() {
    nm_miss=
    for nm_tool in nft ip iptables curl ss; do
        command -v "$nm_tool" >/dev/null 2>&1 || nm_miss="$nm_miss $nm_tool"
    done
    [ -z "$nm_miss" ] && return 0
    if ! command -v apt-get >/dev/null 2>&1; then
        die "Нет apt. Не хватает:$nm_miss. Поставь nftables, iproute2, iptables, curl и запусти снова."
    fi
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y nftables iproute2 iptables curl ca-certificates
}

nm_note_fw() {
    nm_found=
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        nm_found="$nm_found ufw"
    fi
    for nm_unit in firewalld nftables netfilter-persistent fail2ban; do
        if systemctl is-active --quiet "$nm_unit" 2>/dev/null || systemctl is-enabled --quiet "$nm_unit" 2>/dev/null; then
            nm_found="$nm_found $nm_unit"
        fi
    done
    nm_found=${nm_found# }
    if [ -n "$nm_found" ]; then
        printf 'Чужой фаервол: %s. Будет снят в конце установки.\n' "$nm_found" >&2
    fi
}

nm_wait_rules() {
    nm_i=0
    while [ "$nm_i" -lt 30 ]; do
        if nft list table inet netmon >/dev/null 2>&1; then
            return 0
        fi
        nm_i=$((nm_i + 1))
        sleep 1
    done
    return 1
}

nm_drop_one() {
    if systemctl is-active --quiet "$1" 2>/dev/null || systemctl is-enabled --quiet "$1" 2>/dev/null; then
        systemctl disable --now "$1" >/dev/null 2>&1 || true
        nm_off="$nm_off $1"
    fi
}

# Остановка nftables и firewalld сбрасывает весь набор правил, поэтому агент после неё
# перезапускается и заново ставит свою таблицу. nm_rules — стоит ли она в итоге.
nm_drop_fw() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw disable >/dev/null 2>&1 || true
    fi
    nm_drop_one ufw
    nm_drop_one firewalld
    nm_drop_one nftables
    nm_drop_one netfilter-persistent
    nm_drop_one fail2ban
    nm_off=${nm_off# }
    nm_rules=no
    if systemctl is-active --quiet nmagent.service 2>/dev/null; then
        systemctl restart nmagent.service
        if nm_wait_rules; then nm_rules=yes; fi
    fi
}

nm_pick_binary() {
    if [ -n "$nm_binary" ] && [ -f "$nm_binary" ]; then
        printf '%s' "$nm_binary"
        return 0
    fi
    if [ -n "$nm_dir" ] && [ -f "$nm_dir/$1" ]; then
        printf '%s' "$nm_dir/$1"
        return 0
    fi
    return 1
}

nm_fetch_agent() {
    [ -n "$nm_monitor" ] && [ -n "$nm_pin" ] || die "Нет бинарника рядом и не заданы адрес монитора и ключ"
    curl -fsSk --pinnedpubkey "$nm_pin" "https://$nm_monitor/install/nmagent-linux-$nm_a" -o "$nm_tmp/nmagent"
    chmod 700 "$nm_tmp/nmagent"
}

# Комплект с Windows приезжает без бита выполнения, а /tmp бывает noexec.
# Копия в /usr/local/bin запускается в обоих случаях.
nm_runnable() {
    install -m 755 "$1" /usr/local/bin/nmagent.stage
    printf '%s' /usr/local/bin/nmagent.stage
}

nm_install_agent_bin() {
    if systemctl is-active --quiet nmagent.service 2>/dev/null; then
        systemctl stop nmagent.service
    fi
    install -m 755 "$1" /usr/local/bin/nmagent.next
    mv -f /usr/local/bin/nmagent.next /usr/local/bin/nmagent
}

nm_agent_units() {
    cat > /etc/systemd/system/nmagent-restore.service <<'NM_RESTORE'
[Unit]
Description=Restore netmonitor firewall before networking
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target shutdown.target
Wants=network-pre.target
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/nmagent restore --data /var/lib/nmagent
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
NM_RESTORE
    cat > /etc/systemd/system/nmagent.service <<'NM_AGENT'
[Unit]
Description=netmonitor agent
Requires=nmagent-restore.service
After=nmagent-restore.service network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nmagent --data /var/lib/nmagent
Restart=on-failure
RestartSec=2
StateDirectory=nmagent
StateDirectoryMode=0700
UMask=0077
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
NM_AGENT
    chmod 644 /etc/systemd/system/nmagent-restore.service /etc/systemd/system/nmagent.service
    systemctl daemon-reload
    systemctl enable nmagent-restore.service nmagent.service
    systemctl restart nmagent-restore.service
    systemctl restart nmagent.service
    systemctl is-active --quiet nmagent.service
}

nm_enroll() {
    if [ -n "$nm_token" ]; then
        [ -n "$nm_monitor" ] && [ -n "$nm_pin" ] || die "Для первой установки агента нужны адрес монитора и ключ"
        nm_out=$("$1" --data /var/lib/nmagent --monitor "$nm_monitor" --pin "$nm_pin" --token "$nm_token" --enroll-only 2>&1) || die "$nm_out"
        case "$nm_out" in
            kept) printf '%s\n' "агент уже зарегистрирован, токен не понадобился" ;;
            *) printf '%s\n' "$nm_out" ;;
        esac
        return 0
    fi
    if [ -f /var/lib/nmagent/agent.sqlite ]; then
        "$1" --data /var/lib/nmagent --enroll-only
        return 0
    fi
    die "Первая установка агента: нужны --monitor, --pin и --token"
}

nm_do_agent() {
    if nm_src=$(nm_pick_binary "nmagent-linux-$nm_a"); then
        :
    else
        nm_fetch_agent
        nm_src=$nm_tmp/nmagent
    fi
    nm_src=$(nm_runnable "$nm_src")
    nm_enroll "$nm_src"
    nm_install_agent_bin "$nm_src"
    rm -f /usr/local/bin/nmagent.stage
    nm_agent_units
    if [ "$nm_no_fw" = 1 ]; then
        printf 'Агент установлен.\n'
        return 0
    fi
    nm_drop_fw
    if [ "$nm_rules" = yes ]; then
        printf 'Агент установлен, свои правила на месте.\n'
    else
        printf 'Агент установлен. В морде он «ожидает»: свои правила включатся после подтверждения. Чужой фаервол уже снят.\n'
    fi
    printf 'Снято: %s\n' "${nm_off:-ничего}"
}

# Служебное правило пускает nm-update только на адреса GitHub, которые вписаны
# в фильтр агента до соединения. curl идёт ровно на вписанный адрес, каждую
# переадресацию разбираем сами и пускаем только на имена GitHub.
nm_github_host() {
    case "$1" in
        github.com|release-assets.githubusercontent.com|objects.githubusercontent.com) return 0 ;;
    esac
    return 1
}

# Печатает адреса имени и вписывает их в svc4/svc6 на сутки. Наборов нет —
# нет и правила, которое их ждёт: вписывать некуда и не нужно.
nm_admit_host() {
    nm_gh_list=
    nm_gh_batch=
    for nm_gh_ip in $(getent ahosts "$1" 2>/dev/null | awk '{print $1}' | sort -u); do
        case "$nm_gh_ip" in
            127.*|0.*|::|::1|fe80:*|::ffff:*) continue ;;
            *:*) nm_gh_set=svc6 ;;
            *) nm_gh_set=svc4 ;;
        esac
        nm_gh_list="$nm_gh_list $nm_gh_ip"
        nm_gh_batch="${nm_gh_batch}add element inet netmon $nm_gh_set { $nm_gh_ip timeout 86400s }
delete element inet netmon $nm_gh_set { $nm_gh_ip }
add element inet netmon $nm_gh_set { $nm_gh_ip timeout 86400s }
"
    done
    [ -n "$nm_gh_list" ] || return 1
    if nft list set inet netmon svc4 >/dev/null 2>&1; then
        printf '%s' "$nm_gh_batch" | nft -f - || return 1
    fi
    printf '%s\n' $nm_gh_list
}

nm_fetch_github() {
    nm_gh_url=$1
    nm_gh_hop=0
    while :; do
        nm_gh_hop=$((nm_gh_hop + 1))
        [ "$nm_gh_hop" -le 5 ] || { printf 'Слишком много переадресаций\n' >&2; return 1; }
        case "$nm_gh_url" in https://*) ;; *) printf 'Не https: %s\n' "$nm_gh_url" >&2; return 1 ;; esac
        nm_gh_host=${nm_gh_url#https://}
        nm_gh_host=${nm_gh_host%%/*}
        nm_gh_host=${nm_gh_host%%\?*}
        nm_github_host "$nm_gh_host" || { printf 'Чужой адрес: %s\n' "$nm_gh_host" >&2; return 1; }
        nm_gh_addrs=$(nm_admit_host "$nm_gh_host") || { printf 'Адрес %s не вписан в фильтр\n' "$nm_gh_host" >&2; return 1; }
        nm_gh_res=
        for nm_gh_ip in $nm_gh_addrs; do
            nm_gh_to=$nm_gh_ip
            case "$nm_gh_ip" in *:*) nm_gh_to="[$nm_gh_ip]" ;; esac
            nm_gh_res=$(curl -sS --proto '=https' --max-time 180 --resolve "$nm_gh_host:443:$nm_gh_to" \
                -o "$2" -w '%{http_code} %{redirect_url}' "$nm_gh_url") && break
            nm_gh_res=
        done
        [ -n "$nm_gh_res" ] || return 1
        case "${nm_gh_res%% *}" in
            200) return 0 ;;
            301|302|303|307|308) nm_gh_url=${nm_gh_res#* } ;;
            *) printf 'GitHub ответил %s\n' "${nm_gh_res%% *}" >&2; return 1 ;;
        esac
    done
}

# Агент на монитор по кнопке в морде: nmserver пишет файл запроса, nmagent-self.path
# запускает этот же скрипт с --mode self-request.
# Обновление монитора по кнопке в морде: nmserver пишет update.request,
# nm-update.path запускает этот же скрипт с --mode update-request.
nm_update_request() {
    nm_req=${NM_UPDATE_REQUEST:-/var/lib/nmserver/update.request}
    [ -f "$nm_req" ] || return 0
    nm_ver= nm_arch_req= nm_url= nm_sum=
    while IFS= read -r nm_line || [ -n "$nm_line" ]; do
        case "$nm_line" in
            VERSION=*) nm_ver=${nm_line#VERSION=} ;;
            ARCH=*) nm_arch_req=${nm_line#ARCH=} ;;
            URL=*) nm_url=${nm_line#URL=} ;;
            SHA256=*) nm_sum=${nm_line#SHA256=} ;;
        esac
    done < "$nm_req"
    nm_work=$nm_req.running
    mv -f "$nm_req" "$nm_work"
    case "$nm_ver" in ''|*[!0-9.]*) die "Неверная версия" 2 ;; esac
    case "$nm_arch_req" in amd64|arm64) ;; *) die "Неверная архитектура" 2 ;; esac
    case "$nm_url" in
        "https://github.com/Avmbur/NetMonitor/releases/download/v${nm_ver}/netmonitor-linux-${nm_arch_req}.tar.gz") ;;
        *) die "Чужой адрес комплекта" 2 ;;
    esac
    if [ -n "$nm_sum" ] && [ "${#nm_sum}" -ne 64 ]; then die "Неверная сумма" 2; fi
    nm_fetch_github "$nm_url" "$nm_tmp/pkg.tar.gz" || die "Не скачался комплект"
    if [ -n "$nm_sum" ]; then
        printf '%s  %s\n' "$nm_sum" "$nm_tmp/pkg.tar.gz" | sha256sum -c - || die "Сумма не сошлась"
    fi
    tar -xzf "$nm_tmp/pkg.tar.gz" -C "$nm_tmp" || die "Битый архив"
    nm_kit=$nm_tmp/netmonitor-linux-$nm_arch_req
    [ -f "$nm_kit/install.sh" ] || die "В комплекте нет install.sh"
    sh "$nm_kit/install.sh" --mode monitor --self-agent no
}

nm_self_request() {
    nm_req=${NM_SELF_REQUEST:-/var/lib/nmserver/self-agent.request}
    [ -f "$nm_req" ] || return 0
    while IFS= read -r nm_line || [ -n "$nm_line" ]; do
        case "$nm_line" in
            MONITOR=*) nm_monitor=${nm_line#MONITOR=} ;;
            PIN=*) nm_pin=${nm_line#PIN=} ;;
            TOKEN=*) nm_token=${nm_line#TOKEN=} ;;
        esac
    done < "$nm_req"
    nm_work=$nm_req.running
    mv -f "$nm_req" "$nm_work"
    [ -n "$nm_monitor" ] && [ -n "$nm_pin" ] && [ -n "$nm_token" ] || die "Неполный запрос" 2
    case "$nm_monitor" in *"/"*|*" "*|*'$'*|*";"*) die "Неверный адрес монитора" 2 ;; esac
    nm_binary=/usr/local/lib/netmonitor/nmagent-linux-$nm_a
    [ -f "$nm_binary" ] || die "Нет $nm_binary"
    nm_no_fw=1
    nm_do_agent
}

nm_monitor_units() {
    cat > /etc/systemd/system/nmserver.service <<'NM_SERVER'
[Unit]
Description=netmonitor monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nmserver run --data /var/lib/nmserver
Restart=on-failure
RestartSec=2
User=nmserver
Group=nmserver
StateDirectory=nmserver
StateDirectoryMode=0700
UMask=0077
LimitNOFILE=65535
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/nmserver

[Install]
WantedBy=multi-user.target
NM_SERVER
    cat > /etc/systemd/system/nmagent-self.service <<'NM_SELF'
[Unit]
Description=Install nmagent on this monitor host
After=network-online.target nmserver.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/netmonitor/install.sh --mode self-request
NM_SELF
    cat > /etc/systemd/system/nmagent-self.path <<'NM_SELF_PATH'
[Unit]
Description=Watch for a request to install nmagent on this monitor

[Path]
PathChanged=/var/lib/nmserver/self-agent.request
Unit=nmagent-self.service

[Install]
WantedBy=multi-user.target
NM_SELF_PATH
    cat > /etc/systemd/system/nm-update.service <<'NM_UPDATE'
[Unit]
Description=Install a NetMonitor monitor update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/netmonitor/install.sh --mode update-request
NM_UPDATE
    cat > /etc/systemd/system/nm-update.path <<'NM_UPDATE_PATH'
[Unit]
Description=Watch for a NetMonitor monitor update request

[Path]
PathChanged=/var/lib/nmserver/update.request
Unit=nm-update.service

[Install]
WantedBy=multi-user.target
NM_UPDATE_PATH
    chmod 644 /etc/systemd/system/nmserver.service /etc/systemd/system/nmagent-self.service \
        /etc/systemd/system/nmagent-self.path /etc/systemd/system/nm-update.service \
        /etc/systemd/system/nm-update.path
}

nm_self_agent() {
    nm_base="https://$nm_host:$nm_port"
    nm_esc=$(printf '%s' "$nm_password" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '{"login":"adm","password":"%s"}' "$nm_esc" > "$nm_tmp/login"
    nm_code=$(curl -k -sS -o "$nm_tmp/body" -w '%{http_code}' --max-time 20 \
        -c "$nm_tmp/jar" -H 'Content-Type: application/json' --data-binary @"$nm_tmp/login" \
        "$nm_base/ui/login" || true)
    rm -f "$nm_tmp/login"
    [ "$nm_code" = "200" ] || die "Вход в монитор не удался ($nm_code)"
    nm_code=$(curl -k -sS -o "$nm_tmp/body" -w '%{http_code}' --max-time 70 \
        -b "$nm_tmp/jar" -X POST "$nm_base/ui/api/install-self" || true)
    [ "$nm_code" = "200" ] || [ "$nm_code" = "409" ] || die "Агент на мониторе не встал ($nm_code): $(cat "$nm_tmp/body")"
}

nm_do_monitor() {
    nm_srv=$(nm_pick_binary "nmserver-linux-$nm_a") || die "Рядом нет nmserver-linux-$nm_a"
    nm_ag=$(nm_pick_binary "nmagent-linux-$nm_a") || die "Рядом нет nmagent-linux-$nm_a"
    [ -n "$nm_dir" ] && [ -f "$nm_dir/install.sh" ] || die "Монитор ставится из каталога комплекта: sh install.sh"
    nm_have_db=0
    [ -e /var/lib/nmserver/netmon.sqlite ] && nm_have_db=1
    # Агент ставится только командой из морды: агент без базы монитора — монитор, возможно, на другом сервере.
    if [ "$nm_have_db" = 0 ] && [ -f /var/lib/nmagent/agent.sqlite ]; then
        printf 'На этом сервере уже стоит агент netmonitor.\nВозможно, монитор установлен на другом сервере.\n' >&2
        if [ -t 0 ]; then
            printf 'Если переносишь монитор сюда, ставь. Иначе ответь n.\n' >&2
            if ! nm_yes "Поставить монитор на этот сервер?" n; then
                printf 'Монитор не ставился.\n'
                exit 0
            fi
        fi
    fi
    if [ "$nm_have_db" = 1 ]; then
        # База уже есть: адрес и порт в ней, init не вызывается. Свой nmserver держит этот порт — это не «занят».
        if [ -n "$nm_host" ] || [ -n "$nm_port" ]; then
            printf 'База уже есть: адрес и порт берутся из неё, --listen-host и --listen-port не действуют.\n' >&2
        fi
        install -m 755 "$nm_srv" /usr/local/bin/nmserver.next
        nm_ep=$(runuser -u nmserver -- /usr/local/bin/nmserver.next endpoint --data /var/lib/nmserver) ||
            die "Не прочитан адрес монитора из базы"
        nm_host=${nm_ep%:*}
        nm_port=${nm_ep##*:}
        printf 'Монитор уже стоит на %s, база сохраняется.\n' "$nm_ep" >&2
    else
        if [ -z "$nm_host" ]; then
            nm_def=$(nm_default_ip)
            [ -n "$nm_def" ] || nm_def=127.0.0.1
            if [ -t 0 ]; then
                nm_host=$(nm_ask "Адрес монитора" "$nm_def")
            else
                die "Нужен --listen-host"
            fi
        fi
        if [ -z "$nm_port" ]; then
            nm_def=$(nm_suggest_port)
            if [ -t 0 ]; then
                while true; do
                    nm_port=$(nm_ask "Порт" "$nm_def")
                    case "$nm_port" in
                        ''|*[!0-9]*) printf 'Нужен номер порта\n' >&2; continue ;;
                    esac
                    if nm_port_busy "$nm_port"; then
                        nm_def=$(nm_suggest_port)
                        printf 'Порт %s занят, свободен %s\n' "$nm_port" "$nm_def" >&2
                        continue
                    fi
                    break
                done
            else
                nm_port=$nm_def
            fi
        elif nm_port_busy "$nm_port"; then
            die "Порт $nm_port занят"
        fi
    fi
    # Агент на монитор: уже стоит — обновляется из комплекта, иначе вопрос. Вопрос раньше пароля:
    # на стоящем мониторе пароль нужен только для постановки агента.
    if [ -f /var/lib/nmagent/agent.sqlite ]; then
        [ "$nm_self" = no ] || nm_self=keep
    elif [ -z "$nm_self" ]; then
        if [ -t 0 ]; then
            if nm_yes "Поставить агента на этот монитор?"; then nm_self=yes; else nm_self=no; fi
        else
            nm_self=no
        fi
    fi
    nm_need_pass=0
    [ "$nm_have_db" = 1 ] || nm_need_pass=1
    [ "$nm_self" != yes ] || nm_need_pass=1
    if [ "$nm_need_pass" = 1 ] && [ -z "$nm_password" ]; then
        if [ "$nm_pass_stdin" = 1 ]; then
            IFS= read -r nm_password || nm_password=
        elif [ -t 0 ]; then
            nm_password=$(nm_secret "Пароль adm")
        else
            die "Нужен пароль adm: --password-stdin"
        fi
    fi
    [ "$nm_need_pass" = 0 ] || [ -n "$nm_password" ] || die "Пустой пароль"
    id nmserver >/dev/null 2>&1 || useradd --system --home /var/lib/nmserver --shell /usr/sbin/nologin nmserver
    install -d -o nmserver -g nmserver -m 700 /var/lib/nmserver
    install -d -m 755 /usr/local/lib/netmonitor
    install -m 755 "$nm_srv" /usr/local/bin/nmserver.next
    if systemctl is-active --quiet nmserver.service 2>/dev/null; then systemctl stop nmserver.service; fi
    mv -f /usr/local/bin/nmserver.next /usr/local/bin/nmserver
    install -m 755 "$nm_ag" "/usr/local/lib/netmonitor/nmagent-linux-$nm_a"
    install -m 755 "$nm_dir/install.sh" /usr/local/lib/netmonitor/install.sh
    rm -f /usr/local/lib/netmonitor/nmagent-self.sh
    nm_monitor_units
    if [ "$nm_have_db" = 0 ]; then
        printf '%s\n' "$nm_password" | runuser -u nmserver -- /usr/local/bin/nmserver init \
            --data /var/lib/nmserver --password-stdin --listen-host "$nm_host" --listen-port "$nm_port"
    fi
    chown -R nmserver:nmserver /var/lib/nmserver
    systemctl daemon-reload
    systemctl enable nmserver.service nmagent-self.path nm-update.path
    systemctl restart nmserver.service
    systemctl restart nmagent-self.path
    systemctl restart nm-update.path
    systemctl is-active --quiet nmserver.service
    nm_i=0
    nm_code=000
    while [ "$nm_i" -lt 15 ]; do
        nm_code=$(curl -k -sS -o /dev/null -w '%{http_code}' --max-time 5 "https://$nm_host:$nm_port/" 2>/dev/null || true)
        case "$nm_code" in ''|000) ;; *) break ;; esac
        nm_i=$((nm_i + 1))
        sleep 1
    done
    case "$nm_code" in
        ''|000) die "Монитор не ответил на https://$nm_host:$nm_port/" ;;
    esac
    case "$nm_self" in
        yes) nm_self_agent ;;
        keep)
            nm_run=$(nm_runnable "$nm_ag")
            nm_enroll "$nm_run"
            nm_install_agent_bin "$nm_run"
            rm -f /usr/local/bin/nmagent.stage
            nm_agent_units
            ;;
    esac
    if [ "$nm_self" = no ] && [ -f /var/lib/nmagent/agent.sqlite ]; then
        nm_rules=skip
    else
        nm_drop_fw
    fi
    printf 'Монитор: https://%s:%s\n' "$nm_host" "$nm_port"
    case "$nm_self:$nm_rules" in
        yes:yes) printf 'Агент на этом мониторе установлен и подтверждён. Режим обучения, браузер на этот порт пропускается.\n' ;;
        keep:yes) printf 'Агент на этом мониторе обновлён, свои правила на месте.\n' ;;
        no:skip) printf 'Агент на мониторе не трогали, чужой фаервол тоже.\n' ;;
        no:*) printf 'Агент на монитор не ставился. Своего фаервола нет.\n' ;;
        *) printf 'ВНИМАНИЕ: своих правил нет — таблица inet netmon не появилась за 30 с. Смотри journalctl -u nmagent.\n' ;;
    esac
    [ "$nm_rules" = skip ] || printf 'Снято: %s\n' "${nm_off:-ничего}"
    printf 'Браузер один раз спросит про сертификат.\n'
}

main() {
    set -eu
    umask 077
    nm_dir=
    case "$(basename -- "$0" 2>/dev/null || echo sh)" in
        sh|bash|dash) ;;
        *) nm_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) ;;
    esac
    nm_mode= nm_host= nm_port= nm_password= nm_self=
    nm_monitor= nm_pin= nm_token= nm_binary=
    nm_pass_stdin=0 nm_no_fw=0
    nm_off= nm_rules=no nm_work=

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --mode) nm_mode=$2; shift 2 ;;
            --listen-host) nm_host=$2; shift 2 ;;
            --listen-port) nm_port=$2; shift 2 ;;
            --password-stdin) nm_pass_stdin=1; shift ;;
            --self-agent) nm_self=$2; shift 2 ;;
            --monitor) nm_monitor=$2; shift 2 ;;
            --pin) nm_pin=$2; shift 2 ;;
            --token) nm_token=$2; shift 2 ;;
            --binary) nm_binary=$2; shift 2 ;;
            --no-fw) nm_no_fw=1; shift ;;
            *) die "Неизвестный параметр: $1" 2 ;;
        esac
    done
    case "$nm_self" in ''|yes|no) ;; *) die "--self-agent: yes или no" 2 ;; esac
    case "$nm_port" in ''|[0-9]*) ;; *) die "--listen-port: номер порта" 2 ;; esac
    case "$nm_monitor" in *"/"*|*" "*|*'$'*|*";"*) die "Неверный адрес монитора" 2 ;; esac

    [ "$(id -u)" = 0 ] || die "Нужен root"
    nm_a=$(nm_arch)
    nm_tmp=$(mktemp -d /tmp/nm-install.XXXXXX)
    trap 'rm -rf "$nm_tmp"; [ -z "$nm_work" ] || rm -f "$nm_work"; if [ -t 0 ]; then stty echo 2>/dev/null || true; fi' EXIT
    trap 'exit 1' HUP INT TERM
    nm_ensure_pkgs
    if [ "$nm_mode" = self-request ]; then
        nm_self_request
        return 0
    fi
    if [ "$nm_mode" = update-request ]; then
        nm_update_request
        return 0
    fi
    [ "$nm_no_fw" = 1 ] || nm_note_fw

    # Агент ставится только командой из морды: она передаёт --monitor, --pin и --token.
    if [ -z "$nm_mode" ]; then
        if [ -n "$nm_monitor" ]; then nm_mode=agent; else nm_mode=monitor; fi
    fi

    case "$nm_mode" in
        monitor) nm_do_monitor ;;
        agent)
            [ -n "$nm_monitor" ] || die "Агент ставится командой из морды: «Агенты» → «установить агента» → копировать." 2
            nm_do_agent
            ;;
        *) die "Режим: monitor или agent" 2 ;;
    esac
}

main "$@"
