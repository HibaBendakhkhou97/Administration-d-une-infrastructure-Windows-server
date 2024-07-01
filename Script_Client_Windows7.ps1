netsh interface ipv4 show interfaces
netsh interface ipv4 set adress name="Local area Connection" static "10.0.0.5" "255.255.255.0"
netsh interface ipv4 show interfaces
netsh interface ipv4 set dns name="Local area Connection" static "10.0.0.1"
Add-Computer -DomaineName "AuTaza2.ma"
Restart-Computer -Force