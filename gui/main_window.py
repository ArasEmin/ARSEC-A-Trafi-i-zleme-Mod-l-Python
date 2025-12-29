import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import threading
import queue
import time
from datetime import datetime

from network.monitor import NetworkMonitor
from network.packet_analyzer import PacketAnalyzer
from gui.widgets import PacketList, StatsFrame, TrafficChart


class NetworkMonitorApp:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Ana pencere
        self.root = ctk.CTk()
        self.root.title("ARSEC Ağ Takip Monitörü")
        self.root.geometry("1200x700")

        # Değişkenler
        self.is_monitoring = False
        self.monitor_thread = None
        self.packet_queue = queue.Queue()
        self.packets = []
        self.max_packets = 1000

        # Ağ izleyici
        self.monitor = NetworkMonitor()
        self.analyzer = PacketAnalyzer()

        # GUI bileşenlerini oluştur
        self.setup_ui()

        # Paket işleme döngüsü
        self.root.after(100, self.process_packet_queue)

    def setup_ui(self):

        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        left_frame = ctk.CTkFrame(main_frame, width=250)
        left_frame.pack(side="left", fill="y", padx=(0, 10))
        left_frame.pack_propagate(False)

        right_frame = ctk.CTkFrame(main_frame)
        right_frame.pack(side="right", fill="both", expand=True)

        self.setup_control_panel(left_frame)

        self.setup_tabbed_interface(right_frame)

    def setup_control_panel(self, parent):
        title_label = ctk.CTkLabel(
            parent,
            text="ARSEC AĞ TRAFİĞİ",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.pack(pady=20)

        ctk.CTkLabel(parent, text="Ağ Arayüzü:").pack(anchor="w", padx=10, pady=(10, 0))

        self.interface_var = ctk.StringVar(value=self.monitor.get_default_interface())
        interfaces = self.monitor.get_available_interfaces()

        interface_combo = ctk.CTkComboBox(
            parent,
            values=interfaces,
            variable=self.interface_var,
            width=220
        )
        interface_combo.pack(padx=10, pady=(0, 10))

        ctk.CTkLabel(parent, text="Paket Filtresi:").pack(anchor="w", padx=10, pady=(10, 0))

        self.filter_var = ctk.StringVar(value="")
        filter_entry = ctk.CTkEntry(
            parent,
            textvariable=self.filter_var,
            placeholder_text="Örn: tcp, udp, port 80",
            width=220
        )
        filter_entry.pack(padx=10, pady=(0, 20))

        self.start_button = ctk.CTkButton(
            parent,
            text="İzlemeyi Başlat",
            command=self.start_monitoring,
            fg_color="green",
            hover_color="dark green",
            height=40
        )
        self.start_button.pack(padx=10, pady=5)

        self.stop_button = ctk.CTkButton(
            parent,
            text="İzlemeyi Durdur",
            command=self.stop_monitoring,
            fg_color="red",
            hover_color="dark red",
            height=40,
            state="disabled"
        )
        self.stop_button.pack(padx=10, pady=5)

        self.clear_button = ctk.CTkButton(
            parent,
            text="Listeyi Temizle",
            command=self.clear_packets,
            height=35
        )
        self.clear_button.pack(padx=10, pady=20)

        self.stats_frame = StatsFrame(parent)
        self.stats_frame.pack(fill="x", padx=10, pady=20)

    def setup_tabbed_interface(self, parent):

        tabview = ctk.CTkTabview(parent)
        tabview.pack(fill="both", expand=True)

        packets_tab = tabview.add("Paketler")

        self.packet_list = PacketList(packets_tab)
        self.packet_list.pack(fill="both", expand=True, padx=5, pady=5)

        chart_tab = tabview.add("Trafik Grafiği")

        self.traffic_chart = TrafficChart(chart_tab)
        self.traffic_chart.pack(fill="both", expand=True, padx=5, pady=5)

        analysis_tab = tabview.add("Analiz")

        self.setup_analysis_tab(analysis_tab)

    def setup_analysis_tab(self, parent):

        analysis_frame = ctk.CTkFrame(parent)
        analysis_frame.pack(fill="both", expand=True, padx=10, pady=10)

        left_frame = ctk.CTkFrame(analysis_frame)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        ctk.CTkLabel(
            left_frame,
            text="Protokol Dağılımı",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=10)

        self.protocol_text = ctk.CTkTextbox(left_frame, height=200)
        self.protocol_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        right_frame = ctk.CTkFrame(analysis_frame)
        right_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))

        ctk.CTkLabel(
            right_frame,
            text="IP İstatistikleri",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=10)

        self.ip_text = ctk.CTkTextbox(right_frame, height=200)
        self.ip_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        analyze_button = ctk.CTkButton(
            parent,
            text="Mevcut Paketleri Analiz Et",
            command=self.analyze_packets,
            height=40
        )
        analyze_button.pack(pady=10)

    def start_monitoring(self):
        if self.is_monitoring:
            return

        interface = self.interface_var.get()
        packet_filter = self.filter_var.get()

        if not interface:
            messagebox.showerror("Hata", "Lütfen bir ağ arayüzü seçin!")
            return

        try:
            self.monitor.start_monitoring(
                interface=interface,
                packet_filter=packet_filter,
                packet_callback=self.packet_callback
            )

            self.is_monitoring = True
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")

            self.monitor_thread = threading.Thread(
                target=self.monitor.run,
                daemon=True
            )
            self.monitor_thread.start()

            messagebox.showinfo("Başarılı", "Ağ izleme başlatıldı!")

        except Exception as e:
            messagebox.showerror("Hata", f"İzleme başlatılamadı: {str(e)}")

    def stop_monitoring(self):
        if not self.is_monitoring:
            return

        self.monitor.stop_monitoring()
        self.is_monitoring = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")

        messagebox.showinfo("Bilgi", "Ağ izleme durduruldu!")

    def packet_callback(self, packet):
        if len(self.packets) >= self.max_packets:
            self.packets.pop(0)

        packet_info = self.analyzer.analyze_packet(packet)
        self.packets.append(packet_info)

        self.packet_queue.put(packet_info)

    def process_packet_queue(self):
        try:
            while True:
                packet_info = self.packet_queue.get_nowait()

                self.packet_list.add_packet(packet_info)

                self.stats_frame.update_stats(packet_info)

                self.traffic_chart.add_data_point(packet_info)

        except queue.Empty:
            pass
        finally:
            # Her 100 ms'de bir kontrol et
            self.root.after(100, self.process_packet_queue)

    def clear_packets(self):
        self.packets.clear()
        self.packet_list.clear()
        self.traffic_chart.clear()
        self.protocol_text.delete("1.0", "end")
        self.ip_text.delete("1.0", "end")

    def analyze_packets(self):
        if not self.packets:
            messagebox.showinfo("Bilgi", "Analiz edilecek paket yok!")
            return

        protocol_stats = self.analyzer.get_protocol_stats(self.packets)
        self.protocol_text.delete("1.0", "end")

        for protocol, count in protocol_stats.items():
            percentage = (count / len(self.packets)) * 100
            self.protocol_text.insert("end",
                                      f"{protocol}: {count} paket ({percentage:.1f}%)\n")

        ip_stats = self.analyzer.get_ip_stats(self.packets)
        self.ip_text.delete("1.0", "end")

        self.ip_text.insert("end", "Kaynak IP'ler:\n")
        for ip, count in ip_stats['src_ips'].most_common(10):
            self.ip_text.insert("end", f"  {ip}: {count}\n")

        self.ip_text.insert("end", "\nHedef IP'ler:\n")
        for ip, count in ip_stats['dst_ips'].most_common(10):
            self.ip_text.insert("end", f"  {ip}: {count}\n")

    def run(self):
        self.root.mainloop()
