import tkinter as tk
from tkinter import ttk

class SyncGUI(tk.Tk):
    """文件同步工具图形界面
    功能：
    - 显示同步进度条
    - 实时显示日志信息
    - 提供基本操作按钮
    """
    def __init__(self):
        super().__init__()
        self.title("文件同步工具")
        self._setup_ui()
    
    def _setup_ui(self):
        self.progress = ttk.Progressbar(self, mode='determinate')
        self.progress.pack(fill='x', padx=10, pady=10)
        
    def log(self, message, level="INFO"):
        print(f"[{level}] {message}")
        
    def update_progress(self, current, total):
        self.progress['value'] = (current / total) * 100

def main():
    gui = SyncGUI()
    gui.mainloop()

if __name__ == "__main__":
    main() 