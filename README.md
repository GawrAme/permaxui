# PermaXUI

Ini adalah [3X-UI](https://github.com/MHSanaei/3x-ui) yang sudah saya tambahkan untuk konfigurasi koneksi WebSocket, HTTPUpgrade, dan gRPC pada single port ReverseProxy. </br>
Sudah pre-setup config.json dan database setup </br>

Disclaimer: Proyek ini hanya untuk pembelajaran dan komunikasi pribadi, mohon jangan menggunakannya untuk tujuan ilegal. </br>
Credit aplikasi full to [MHSanaei](https://github.com/MHSanaei) </br>
saya hanya menambahkan instalasi sederhana bagi pemula. </br>

# Special Thanks to
- [MHSanaei](https://github.com/MHSanaei)
- [hamid-gh98](https://github.com/hamid-gh98)

# List Protocol yang support
- VLess
- VMess
- Trojan
- Shadowsocks2022 (2022-blake3-aes-128-gcm)

# Yang harus dipersiapkan
- VPS dengan minimal spek 1 Core 2 GB ram
- Domain yang sudah di pointing ke CloudFlare atau hosting name pilihan kalian
- Pemahaman dasar perintah Linux

# Sistem VM yang dapat digunakan
- Debian 12 [**RECOMMENDED**] </br>

# Instalasi
  ```html
 apt-get update && apt-get upgrade -y && apt dist-upgrade -y && update-grub && reboot
 ```
Pastikan anda sudah login sebagai root sebelum menjalankan perintah dibawah
Jalankan step by step
 ```html
apt-get update && apt-get install -y screen
 ```
 ```html
screen -S 3xui
 ```
Posisi didalam screen
 ```
curl -fsSL https://github.com/GawrAme/permaxui/raw/main/install.sh | bash
 ```
Jadi jika ada koneksi terputus dari aplikasih SSH kalian macam Putty, JuiceSSH, dan semacam nya, progress tetap berjalan.
Jika ingin cek kembali progress installasi nya ketik
```html
screen -r 3xui
 ```

Buka panel 3XUI dengan mengunjungi https://domainmu/randompath <br>

Beberapa CLI X-UI yang perlu kalian ingat 
- x-ui              - Admin Management Script
- x-ui start        - Start 
- x-ui stop         - Stop
- x-ui restart      - Restart 
- x-ui status       - Current Status
- x-ui settings     - Current Settings 
- x-ui enable       - Enable Autostart on OS Startup 
- x-ui disable      - Disable Autostart on OS Startup
- x-ui log          - Check logs 
- x-ui banlog       - Check Fail2ban ban logs
- x-ui update       - Update

# Cloudflare Sett

Pastikan SSL/TLS Setting pada cloudflare sudah di set menjadi full
![image](https://github.com/GawrAme/MarLing/assets/97426017/3aeedf09-308e-41b0-9640-50e4abb77aa0) </br>

Lalu pada tab **Network** pastikan gRPC dan WebSocket sudah ON 
![image](https://github.com/GawrAme/MarLing/assets/97426017/65d9b413-fda4-478a-99a5-b33d8e5fec3d)



# Setting 3XUI LimitIP
 
 Saat masuk ke panel, ke menu konfigurasi Xray, dan set sama persis dengan gambar dibawah <br>
<img width="1635" height="835" alt="image" src="https://github.com/user-attachments/assets/e51cfc09-4edc-47df-8365-a9c1de405789" />
</br>
Jika sudah di sett, simpan lalu restart Xray

Jika ada typo atau saran bisa PM ke saya di :<a href="https://t.me/EkoLing" target=”_blank”><img src="https://img.shields.io/static/v1?style=for-the-badge&logo=Telegram&label=Telegram&message=Click%20Here&color=blue"></a><br>
Jika anda berminat bisa join ke Telegram channel saya di :<a href="https://t.me/LingVPN" target=”_blank”><img src="https://img.shields.io/static/v1?style=for-the-badge&logo=Telegram&label=Telegram&message=Click%20Here&color=blue"></a><br>
