import netifaces
import sqlite3
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
from tabulate import tabulate
import json
from datetime import datetime
import os

DB_FILE = "arp_scan_v1.db"
# Время жизни кэша базы производителей в днях
VENDOR_DB_CACHE_DAYS = 7


def update_vendor_database():
    """
    Обновляет базу данных производителей MAC-адресов, если это необходимо.
    Обновление выполняется только раз в указанное количество дней.
    """
    try:
        # Путь к файлу-маркеру с датой последнего обновления
        update_marker_file = os.path.expanduser("~/.mac_vendor_update")
        need_update = True

        # Проверяем, нужно ли обновлять базу
        if os.path.exists(update_marker_file):
            # Получаем время последнего обновления
            last_update_time = os.path.getmtime(update_marker_file)
            current_time = datetime.now().timestamp()
            days_since_update = (current_time - last_update_time) / (60 * 60 * 24)

            # Если база обновлялась недавно, пропускаем обновление
            if days_since_update < VENDOR_DB_CACHE_DAYS:
                print(f"Vendor database is up-to-date (last updated {int(days_since_update)} days ago)")
                need_update = False

        if need_update:
            print("Updating vendor database... This may take a few moments...")
            mac_lookup = MacLookup()
            mac_lookup.update_vendors()

            # Создаем файл-маркер с текущей датой
            with open(update_marker_file, "w") as f:
                f.write(datetime.now().isoformat())

            print("Vendor database updated successfully!")

        return True
    except Exception as e:
        print(f"Warning: Failed to update vendor database: {e}")
        return False


def get_vendor(mac_address, mac_lookup):
    """
    Получает информацию о производителе по MAC-адресу.
    """
    try:
        vendor = mac_lookup.lookup(mac_address)
        return vendor
    except Exception:
        return None


def get_default_interface_and_ip_range():
    try:
        # Получение информации о шлюзе по умолчанию
        gateways = netifaces.gateways()
        default_gateway = gateways["default"][netifaces.AF_INET]
        gateway_ip = default_gateway[0]  # IP-адрес шлюза
        interface = default_gateway[1]  # Интерфейс

        # Получение информации об интерфейсе
        iface_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        ip = iface_info["addr"]
        netmask = iface_info["netmask"]

        # Расчет маски подсети в битах (CIDR notation)
        netmask_bits = sum([bin(int(x)).count("1") for x in netmask.split(".")])
        ip_range = f"{ip}/{netmask_bits}"

        return interface, ip_range
    except Exception as e:
        raise RuntimeError(f"Failed to detect interface or IP range: {e}")


def arp_scan(ip_range, interface):
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, iface=interface, timeout=2, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Создание таблицы устройств, если она не существует
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY,
        ip TEXT,
        vendor TEXT,
        first_seen TEXT
    )
    """)

    conn.commit()
    return conn


def load_known_devices(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT mac FROM devices")
    return set(row[0] for row in cursor.fetchall())


def save_new_devices(conn, new_devices):
    cursor = conn.cursor()

    for dev in new_devices:
        # Проверяем, существует ли уже устройство в базе данных
        cursor.execute("SELECT mac FROM devices WHERE mac = ?", (dev["mac"],))
        exists = cursor.fetchone()

        if not exists:
            # Добавляем только если устройства нет в базе
            cursor.execute(
                "INSERT INTO devices (mac, ip, vendor, first_seen) VALUES (?, ?, ?, ?)",
                (dev["mac"], dev["ip"], dev["vendor"], dev["first_seen"]),
            )

    conn.commit()


def update_existing_device_ip(conn, mac, ip):
    # Обновляем IP-адрес для существующего устройства, если он изменился
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET ip = ? WHERE mac = ?", (ip, mac))
    conn.commit()


if __name__ == "__main__":
    print("ARP Network Scanner starting...")

    # Обновляем базу производителей MAC-адресов в начале
    print("\n=== Vendor Database ===")
    update_vendor_database()
    # Создаем единый экземпляр MacLookup для всей программы
    mac_lookup = MacLookup()
    print("======================\n")

    try:
        print("=== Network Setup ===")
        interface, ip_range = get_default_interface_and_ip_range()
        print(f"Interface: {interface}")
        print(f"IP Range: {ip_range}")
        print("====================\n")
    except Exception as e:
        print(f"Error: {e}")
        exit(1)

    print("=== Database Operations ===")
    print("Initializing database...")
    conn = init_db()
    print("Loading known devices...")
    known_macs = load_known_devices(conn)
    print(f"Found {len(known_macs)} devices in database.")
    print("=========================\n")

    print("=== Scanning Network ===")
    print("Starting ARP scan...")
    devices = arp_scan(ip_range, interface)
    print(f"ARP scan completed. Found {len(devices)} devices.")
    print("======================\n")

    if devices:
        print("=== Processing Results ===")
        print("Looking up vendor information...")

        mac_cache = {}
        table = []
        json_output = []
        new_devices = []

        total_devices = len(devices)
        processed = 0

        for device in devices:
            mac = device["mac"]
            ip = device["ip"]

            if mac not in mac_cache:
                mac_cache[mac] = get_vendor(mac, mac_lookup)
                processed += 1

                # Отображаем прогресс для больших сетей
                if total_devices > 10 and processed % 5 == 0:
                    print(f"Progress: {processed}/{total_devices} devices processed")

            vendor = mac_cache[mac] or "Unknown"

            # Информация об устройстве для вывода
            device_info = {"ip": ip, "mac": mac, "vendor": vendor}
            table.append([ip, mac, vendor])
            json_output.append(device_info)

            # Если MAC-адрес не был в базе раньше, добавляем его как новое устройство
            if mac not in known_macs:
                device_info["first_seen"] = datetime.now().isoformat()
                new_devices.append(device_info)
            else:
                # Обновляем IP-адрес для существующего устройства
                update_existing_device_ip(conn, mac, ip)

        # Вывод всех обнаруженных устройств
        print("\n=== Scan Results ===")
        print(tabulate(table, headers=["IP", "MAC", "Vendor"]))
        print(f"\nTotal devices found: {len(devices)}")

        # Сохранение всех результатов в JSON-файл
        with open("arp_scan_result.json", "w") as f:
            json.dump(json_output, f, indent=4)
        print("Results saved to arp_scan_result.json")

        # Если обнаружены новые устройства, сохраняем их в базу и выводим информацию
        if new_devices:
            print("\n=== New Devices ===")
            save_new_devices(conn, new_devices)
            print(f"🔔 {len(new_devices)} new device(s) detected since last scan:")
            print(tabulate([[d["ip"], d["mac"], d["vendor"]] for d in new_devices], headers=["IP", "MAC", "Vendor"]))
            print("====================")
        else:
            print("\n=== New Devices ===")
            print("No new devices detected since last scan.")
            print("====================")
    else:
        print("\n=== Scan Results ===")
        print("No devices found.")
        print("====================")

    print("\nARP Network Scanner completed.")
