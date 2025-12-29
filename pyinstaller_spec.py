import PyInstaller.__main__
import os

# Çalışma dizini
current_dir = os.path.dirname(os.path.abspath(__file__))

PyInstaller.__main__.run([
    'main.py',
    '--name=ARSECNetworkMonitor',
    '--onefile',
    '--windowed',
    '--clean',
    '--noconfirm',
    # Gizli import'lar (Scapy için gerekli)
    '--hidden-import=scapy',
    '--hidden-import=scapy.layers',
    '--hidden-import=scapy.layers.inet',
    '--hidden-import=scapy.layers.dns',
    '--hidden-import=customtkinter',
    '--hidden-import=matplotlib',
    '--hidden-import=matplotlib.backends.backend_tkagg',
    '--hidden-import=PIL',
    '--hidden-import=PIL._tkinter_finder',

    # Veri dosyaları
    '--add-data=requirements.txt;.',
    '--add-data=README.md;.',

    # DLL'leri dahil et (Windows için)
    '--collect-all=scapy',
    '--collect-all=customtkinter',

    # Konsolu gizle (GUI uygulaması için)
    '--noconsole',

    # Optimizasyon
    '--optimize=2',
])