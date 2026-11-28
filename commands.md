# portscan: команды для запуска

Все команды выполняются в WSL (Ubuntu), в папке с кодом сканера.
Сканеру нужны raw-сокеты, поэтому он запускается через `sudo`.

## 1. Подготовка (один раз)

```bash
cd /mnt/c/путь/к/папке      # диск Windows виден в WSL как /mnt/c
python3 --version             # нужна версия 3.10 или новее
sudo apt install socat        # для эхо-сервера
sudo apt install tcpdump      # по желанию: смотреть пакеты
```

## 2. Тестовые серверы

Каждый сервер запускается в отдельном терминале WSL и работает, пока его не остановят (Ctrl+C).

### HTTP — TCP 8000

```bash
python3 -m http.server 8000
```

### ECHO — TCP и UDP 7777

```bash
socat TCP-LISTEN:7777,fork,reuseaddr EXEC:cat &
socat UDP-LISTEN:7777,fork EXEC:cat
```

Первая команда уходит в фон (`&`), вторая занимает терминал.

### DNS — сервер, которым пользуется WSL

Запускать ничего не нужно. Адрес сервера:

```bash
awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf
```

### Открытый UDP-порт без своих серверов

В WSL работает chrony, он слушает UDP 323 на `127.0.0.1`.

### Что сейчас слушает машина

```bash
sudo ss -tlnp     # TCP-порты
sudo ss -ulnp     # UDP-порты
```

## 3. Запуск сканера

Формат:

```
sudo python3 portscan.py [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...
```

| Опция | Значение |
|---|---|
| `--timeout N` | таймаут ожидания ответа в секундах, по умолчанию 2 |
| `-j N`, `--num-threads N` | принимается, но не используется: сканер работает на select |
| `-v`, `--verbose` | время ответа в мс для TCP |
| `-g`, `--guess` | определение протокола: HTTP, DNS, ECHO |

### Примеры из условия

```bash
sudo python3 portscan.py 1.1.1.1 tcp/80 tcp/12000-12500 udp/3000-3100,3200,3300-4000
sudo python3 portscan.py 1.1.1.1 tcp udp/40000
```

### TCP (нужен HTTP-сервер на 8000)

```bash
sudo python3 portscan.py 127.0.0.1 tcp/7990-8010      # TCP 8000
sudo python3 portscan.py -v 127.0.0.1 tcp/8000        # TCP 8000 0.05 (время будет другим)
sudo python3 portscan.py 127.0.0.1 tcp                # все TCP-порты
```

### UDP

```bash
sudo python3 portscan.py 127.0.0.1 udp/320-330        # UDP 323
sudo python3 portscan.py 127.0.0.1 udp                # все UDP-порты
```

### Определение протокола (нужны HTTP-сервер и эхо)

```bash
sudo python3 portscan.py -g 127.0.0.1 tcp/7777,8000 udp/323,7777
```

Ожидаемый вывод:

```
TCP 7777 ECHO
TCP 8000 HTTP
UDP 323 -
UDP 7777 ECHO
```

С временем ответа:

```bash
sudo python3 portscan.py -v -g 127.0.0.1 tcp/7777,8000
```

DNS:

```bash
sudo python3 portscan.py -g $(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf) tcp/53 udp/53
```

Ожидаемо `UDP 53 DNS`, и `TCP 53 DNS`, если сервер принимает TCP.

### Все порты по TCP и UDP

```bash
sudo python3 portscan.py 127.0.0.1
```

### Внешний хост (его владельцы разрешают сканирование)

```bash
sudo python3 portscan.py -v -g $(getent ahostsv4 scanme.nmap.org | awk '{print $1; exit}') tcp/1-1000
```

UDP-результаты для внешних хостов из WSL ненадёжны: ICMP-ответы могут теряться в NAT Windows.

## 4. Проверка обработки ошибок

Неверные аргументы — у каждого `portscan: error: ...` и код 2:

```bash
for a in "1.1.1.1 tcp/80-70" "300.1.1.1" "1.1.1.1 icmp/1" "1.1.1.1 tcp/0" "1.1.1.1 tcp/80,,90" "--timeout -1 1.1.1.1"; do python3 portscan.py $a; echo "код: $?"; done
```

Запуск без `sudo` — сообщение `portscan: raw sockets need root, run with sudo` в stderr:

```bash
python3 portscan.py 127.0.0.1 tcp/80
```

## 5. Проверка, что соединения не остаются полуоткрытыми

В отдельном терминале, пока идёт скан порта 8000:

```bash
sudo tcpdump -i lo -n port 8000
```

После строки с `[S.]` (SYN-ACK) должна идти строка с `[R]` (RST). Строки `[.]` (одиночный ACK) быть не должно.

## 6. Остановка серверов

```bash
pkill socat       # оба эхо-сервера
```

`http.server` останавливается Ctrl+C в его терминале.
