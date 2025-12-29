import customtkinter as ctk
from tkinter import ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import defaultdict
from datetime import datetime
import matplotlib

matplotlib.use('TkAgg')


class PacketList(ctk.CTkFrame):

    def __init__(self, parent):
        super().__init__(parent)

        self.tree = ttk.Treeview(
            self,
            columns=("No", "Zaman", "Kaynak", "Hedef", "Protokol", "Uzunluk", "Bilgi"),
            show="headings",
            height=20
        )

        # Sütun başlıkları
        columns = [
            ("No", 50),
            ("Zaman", 120),
            ("Kaynak", 150),
            ("Hedef", 150),
            ("Protokol", 80),
            ("Uzunluk", 80),
            ("Bilgi", 300)
        ]

        for col, width in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, minwidth=width)

        # Scrollbar
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Düzen
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Paket sayacı
        self.packet_count = 0

        # Tag renklerini önceden tanımla
        self._setup_tag_colors()

    def _setup_tag_colors(self):
        color_map = {
            'tcp': '#3498db',
            'udp': '#e74c3c',
            'http': '#2ecc71',
            'https': '#f39c12',
            'dns': '#9b59b6',
            'icmp': '#1abc9c',
            'other': '#95a5a6'
        }

        for tag, color in color_map.items():
            self.tree.tag_configure(tag, background=color)

    def add_packet(self, packet_info):
        self.packet_count += 1

        values = (
            self.packet_count,
            packet_info.get('timestamp', ''),
            packet_info.get('src_ip', ''),
            packet_info.get('dst_ip', ''),
            packet_info.get('protocol', ''),
            packet_info.get('length', ''),
            packet_info.get('info', '')
        )

        # Renk kodlama
        tag = self.get_protocol_tag(packet_info.get('protocol', ''))
        self.tree.insert("", "end", values=values, tags=(tag,))

        # Otomatik scroll
        self.tree.see(self.tree.get_children()[-1])

    def get_protocol_tag(self, protocol):
        colors = {
            'TCP': 'tcp',
            'UDP': 'udp',
            'HTTP': 'http',
            'HTTPS': 'https',
            'DNS': 'dns',
            'ICMP': 'icmp'
        }

        return colors.get(protocol, 'other')

    def clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packet_count = 0


class StatsFrame(ctk.CTkFrame):

    def __init__(self, parent):
        super().__init__(parent)

        self.stats = defaultdict(int)
        self.labels = {}

        # İstatistik başlığı
        title = ctk.CTkLabel(self, text="İstatistikler", font=ctk.CTkFont(weight="bold"))
        title.pack(pady=(0, 10))

        # İstatistik etiketleri
        stats_data = [
            ("Toplam Paket:", "total"),
            ("TCP:", "TCP"),
            ("UDP:", "UDP"),
            ("HTTP:", "HTTP"),
            ("HTTPS:", "HTTPS"),
            ("DNS:", "DNS"),
            ("ICMP:", "ICMP")
        ]

        for text, key in stats_data:
            frame = ctk.CTkFrame(self, fg_color="transparent")
            frame.pack(fill="x", padx=5, pady=2)

            label_text = ctk.CTkLabel(frame, text=text, width=80, anchor="w")
            label_text.pack(side="left")

            value_label = ctk.CTkLabel(frame, text="0", width=50, anchor="e")
            value_label.pack(side="right")

            self.labels[key] = value_label

    def update_stats(self, packet_info):
        protocol = packet_info.get('protocol', '')

        self.stats['total'] += 1
        self.stats[protocol] += 1

        # Etiketleri güncelle
        for key, label in self.labels.items():
            label.configure(text=str(self.stats[key]))


class TrafficChart(ctk.CTkFrame):

    def __init__(self, parent, max_points=100):
        super().__init__(parent)

        self.max_points = max_points
        self.data_points = []
        self.timestamps = []
        self.update_interval = 500
        self.last_update = 0

        import matplotlib
        matplotlib.use('Agg')

        self.fig, self.ax = plt.subplots(figsize=(8, 4), dpi=80)
        self.fig.patch.set_facecolor('#2b2b2b')
        self.ax.set_facecolor('#2b2b2b')

        self.ax.tick_params(colors='white', labelsize=8)
        self.ax.xaxis.label.set_color('white')
        self.ax.yaxis.label.set_color('white')
        self.ax.title.set_color('white')

        for spine in self.ax.spines.values():
            spine.set_color('white')

        self.ax.set_xlabel('Son Paketler', fontsize=10)
        self.ax.set_ylabel('Boyut (bayt)', fontsize=10)
        self.ax.set_title('Ağ Trafiği - Son 100 Paket', fontsize=12, pad=10)

        self.canvas = FigureCanvasTkAgg(self.fig, self)
        self.canvas.draw()
        canvas_widget = self.canvas.get_tk_widget()
        canvas_widget.pack(fill="both", expand=True, padx=5, pady=5)

        self.line, = self.ax.plot([], [], color='#3498db', linewidth=1.5, alpha=0.8)

        self.ax.grid(True, alpha=0.2, color='white', linestyle='--')

        self.ax.set_xlim(0, self.max_points - 1)
        self.ax.set_ylim(0, 1500)

    def add_data_point(self, packet_info):
        length = packet_info.get('length', 0)

        self.data_points.append(length)
        self.timestamps.append(datetime.now())

        if len(self.data_points) > self.max_points:
            self.data_points.pop(0)
            self.timestamps.pop(0)

        current_time = datetime.now().timestamp() * 1000  # ms cinsinden
        if current_time - self.last_update > self.update_interval:
            self.update_chart()
            self.last_update = current_time

    def update_chart(self):
        if not self.data_points:
            return

        try:
            self.line.set_data(range(len(self.data_points)), self.data_points)

            if len(self.data_points) > 1:
                self.ax.set_xlim(0, len(self.data_points) - 1)

                y_max = max(self.data_points) * 1.1
                y_min = min(self.data_points) * 0.9
                self.ax.set_ylim(max(0, y_min), max(100, y_max))

            if len(self.timestamps) > 0:
                time_labels = []
                indices = []

                if len(self.timestamps) <= 5:
                    for i, ts in enumerate(self.timestamps):
                        time_labels.append(ts.strftime('%H:%M:%S'))
                        indices.append(i)
                else:
                    step = max(1, len(self.timestamps) // 5)
                    for i in range(0, len(self.timestamps), step):
                        time_labels.append(self.timestamps[i].strftime('%H:%M:%S'))
                        indices.append(i)

                self.ax.set_xticks(indices)
                self.ax.set_xticklabels(time_labels, rotation=45, ha='right', fontsize=8)

            self.canvas.draw_idle()

        except Exception as e:
            print(f"Grafik güncelleme hatası: {e}")

    def clear(self):
        self.data_points.clear()
        self.timestamps.clear()
        self.line.set_data([], [])
        self.ax.set_xlim(0, self.max_points - 1)
        self.ax.set_ylim(0, 1500)
        try:
            self.canvas.draw()
        except:
            pass
