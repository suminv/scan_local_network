from mac_vendor_lookup import MacLookup

mac = MacLookup()
mac.update_vendors()  # <- This can take a few seconds for the download
    
def find_mac(mac_address):
    print(mac.lookup(mac_address))

