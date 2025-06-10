import subprocess
import platform

def block_ip(ip_address):
    """Блокує вихідний трафік на вказану IP-адресу через Windows Firewall."""
    if platform.system() != "Windows":
        print("Блокування через Firewall підтримується тільки на Windows.")
        return False, "Not Windows"
    rule_name = f"Block_{ip_address.replace('.', '_')}"
    try:
        check_command = f'netsh advfirewall firewall show rule name="{rule_name}"'
        process = subprocess.run(check_command, shell=True, capture_output=True, text=True, check=False)
        if process.returncode == 0 and rule_name in process.stdout:
            print(f"Правило '{rule_name}' для IP {ip_address} вже існує.")
            return True, f"Rule for {ip_address} already exists."
        command = (
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f'dir=out action=block remoteip="{ip_address}" '
            f'enable=yes profile=any'
        )
        subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"IP-адреса {ip_address} успішно заблокована (правило '{rule_name}').")
        return True, f"IP {ip_address} blocked successfully."
    except subprocess.CalledProcessError as e:
        error_message = f"Помилка при блокуванні IP {ip_address}: {e.stderr}"
        if "адміністратора" in e.stderr.lower() or "administrator" in e.stderr.lower() or "elevated" in e.stderr.lower():
            error_message += "\nСпробуйте запустити програму з правами адміністратора."
        print(error_message)
        return False, error_message
    except Exception as e:
        print(f"Неочікувана помилка: {e}")
        return False, str(e)

def unblock_ip(ip_address):
    """Видаляє правило блокування для вказаної IP-адреси."""
    if platform.system() != "Windows":
        print("Розблокування через Firewall підтримується тільки на Windows.")
        return False, "Not Windows"

    rule_name = f"Block_{ip_address.replace('.', '_')}"
    try:
        command = f'netsh advfirewall firewall delete rule name="{rule_name}" remoteip="{ip_address}"'
        subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"Правило блокування для IP {ip_address} ('{rule_name}') успішно видалено.")
        return True, f"IP {ip_address} unblocked successfully."
    except subprocess.CalledProcessError as e:
        error_message = f"Помилка при розблокуванні IP {ip_address}: {e.stderr}"
        if "адміністратора" in e.stderr.lower() or "administrator" in e.stderr.lower() or "elevated" in e.stderr.lower():
             error_message += "\nСпробуйте запустити програму з правами адміністратора."
        print(error_message)
        return False, error_message
    except Exception as e:
        print(f"Неочікувана помилка при розблокуванні: {e}")
        return False, str(e)


if __name__ == "__main__":
    test_ip_to_block = "1.2.3.4"
    print(f"Спроба заблокувати {test_ip_to_block}...")
    success, message = block_ip(test_ip_to_block)
    print(f"Результат блокування: {success}, Повідомлення: {message}")

    if success:
        input(f"IP {test_ip_to_block} заблоковано. Перевірте (напр., ping {test_ip_to_block}). Натисніть Enter для розблокування...")
        print(f"Спроба розблокувати {test_ip_to_block}...")
        success_unblock, message_unblock = unblock_ip(test_ip_to_block)
        print(f"Результат розблокування: {success_unblock}, Повідомлення: {message_unblock}")
    else:
        print("Блокування не вдалося, тому розблокування не виконується.")