import socket
import psutil
from scapy.all import sniff
import threading
import time


class NetworkMonitor:

    def __init__(self, gui_callback=None):
        self.is_monitoring = False
        self.sniff_thread = None
        self.packet_callback = None
        self.packet_filter = ""
        self.interface = None
        self.stop_sniffing = threading.Event()
        self.sniff_timeout = 2
        self.gui_callback = gui_callback
        
    def get_available_interfaces(self):
        interfaces = []
        for iface, addrs in psutil.net_if_addrs().items():
            if iface != 'lo' and iface not in ['lo0']:
                interfaces.append(iface)
        return interfaces if interfaces else ['eth0', 'wlan0']
        
    def get_default_interface(self):
        interfaces = self.get_available_interfaces()
        return interfaces[0] if interfaces else 'eth0'
        
    def start_monitoring(self, interface, packet_filter="", packet_callback=None):
        self.interface = interface
        self.packet_filter = packet_filter
        self.packet_callback = packet_callback
        self.is_monitoring = True
        self.stop_sniffing.clear()
        
    def stop_monitoring(self):
        self.is_monitoring = False
        self.stop_sniffing.set()
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=1)
        
    def run(self):
        print(f"İzleme başlatıldı: {self.interface}, Filtre: {self.packet_filter}")
        
        try:
            while not self.stop_sniffing.is_set() and self.is_monitoring:
                try:
                    sniff(
                        iface=self.interface,
                        filter=self.packet_filter,
                        prn=self._process_packet,
                        store=False,
                        stop_filter=lambda x: self.stop_sniffing.is_set(),
                        timeout=self.sniff_timeout
                    )
                except Exception as e:
                    print(f"Sniff hatası: {e}")
                    time.sleep(0.1)  # Kısa bir bekleme
                    
        except Exception as e:
            print(f"İzleme döngüsü hatası: {e}")
        finally:
            print("İzleme durduruldu")
            
    def _process_packet(self, packet):
        """Yakalanan paketi işle"""
        if self.packet_callback and self.is_monitoring:
            try:
                self.packet_callback(packet)
            except Exception as e:
                print(f"Paket callback hatası: {e}")
                
    def get_network_info(self):
        info = {}
        
        # Ağ arayüz bilgileri
        for iface, addrs in psutil.net_if_addrs().items():
            info[iface] = []
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    info[iface].append({
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                    
        stats = psutil.net_io_counters(pernic=True)
        return info, stats
