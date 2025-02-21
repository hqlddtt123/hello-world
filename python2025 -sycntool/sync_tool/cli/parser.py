#!/usr/bin/env python3
import os
import shutil
import logging
import argparse
import xxhash  # 更快的非加密哈希算法
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Thread
import queue
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path  # 更规范的路径处理
from typing import Optional  # 类型提示

class SyncLogger:
    """专用日志记录模块"""
    def __init__(self, log_file='sync.log'):
        self.logger = logging.getLogger('FileSync')
        self.logger.setLevel(logging.INFO)
        
        # 文件处理器
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        file_handler.setFormatter(file_formatter)
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_formatter = ColoredFormatter('%(message)s')
        console_handler.setFormatter(console_formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

class ColoredFormatter(logging.Formatter):
    """带颜色的控制台日志"""
    COLORS = {
        'WARNING': '\033[93m',
        'ERROR': '\033[91m',
        'INFO': '\033[94m',
        'ENDC': '\033[0m'
    }
    
    def format(self, record):
        message = super().format(record)
        return f"{self.COLORS.get(record.levelname, '')}{message}{self.COLORS['ENDC']}"

class FileSynchronizer:
    """高级文件同步工具"""
    
    def __init__(self, src, dst, log_file='sync.log', conflict_suffix='.conflict', conflict_strategy='timestamp', time_threshold=60):
        self.src = os.path.normpath(src)
        self.dst = os.path.normpath(dst)
        self.log_file = log_file
        self.conflict_suffix = conflict_suffix
        self.conflict_strategy = conflict_strategy
        self.time_threshold = time_threshold
        self.setup_logging()
        
        # 初始化文件索引
        self.src_index = {}
        self.dst_index = {}
        self.operations = []
        
    def setup_logging(self):
        """配置日志记录系统"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        
    def scan_directory(self, path):
        """深度扫描目录并建立文件索引"""
        try:
            file_index = {}
            for root, dirs, files in os.walk(path):
                for name in files + dirs:
                    full_path = os.path.join(root, name)
                    rel_path = os.path.relpath(full_path, path)
                    if os.path.islink(full_path):
                        continue  # 跳过符号链接
                    try:
                        stat = os.stat(full_path)
                        file_index[rel_path] = {
                            'size': stat.st_size,
                            'mtime': stat.st_mtime,
                            'is_dir': os.path.isdir(full_path),
                            'hash': self.calculate_hash(full_path) if not os.path.isdir(full_path) else None
                        }
                    except PermissionError as e:
                        self.logger.error(f"权限错误 {full_path}: {e}", exc_info=True)
                    except OSError as e:
                        self.logger.error(f"系统错误 {full_path}: {e}", exc_info=True)
            return file_index
        except Exception as e:
            self.logger.error(f"目录扫描失败: {str(e)}", exc_info=True)
            raise SyncError("目录扫描失败") from e
    
    def calculate_hash(self, filepath):
        """优化哈希计算性能"""
        if os.path.isdir(filepath):
            return None
        hasher = xxhash.xxh64()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def compare_and_index_files(self):
        """高级文件比较逻辑"""
        self.src_index = self.scan_directory(self.src)
        self.dst_index = self.scan_directory(self.dst)
        
        all_files = set(self.src_index.keys()) | set(self.dst_index.keys())
        
        for rel_path in all_files:
            src_file = self.src_index.get(rel_path)
            dst_file = self.dst_index.get(rel_path)
            
            # 处理删除/新增情况
            if not src_file:
                self.handle_missing(rel_path, self.dst, self.src, '→')
                continue
            if not dst_file:
                self.handle_missing(rel_path, self.src, self.dst, '←')
                continue
                
            # 处理目录
            if src_file['is_dir'] or dst_file['is_dir']:
                if src_file['is_dir'] != dst_file['is_dir']:
                    logging.warning(f"类型冲突 {rel_path}: 目录/文件类型不匹配")
                continue
                
            # 精确比较文件内容
            if src_file['hash'] != dst_file['hash']:
                self.handle_conflict(rel_path, src_file, dst_file)
    
    def handle_conflict(self, rel_path, src_file, dst_file):
        """可配置的冲突解决策略"""
        src_path = os.path.join(self.src, rel_path)
        dst_path = os.path.join(self.dst, rel_path)
        
        if self.conflict_strategy == 'timestamp':
            time_diff = src_file['mtime'] - dst_file['mtime']
            if abs(time_diff) > self.time_threshold:
                if time_diff > 0:
                    self.operations.append(('update', src_path, dst_path))
                else:
                    self.operations.append(('update', dst_path, src_path))
            else:
                conflict_path = f"{dst_path}{self.conflict_suffix}"
                self.operations.append(('conflict', dst_path, conflict_path))
                logging.warning(f"创建冲突副本: {conflict_path}")
        elif self.conflict_strategy == 'manual':
            # 弹出对话框让用户选择
            self._resolve_manual_conflict(rel_path)
    
    def handle_missing(self, rel_path, source_dir, target_dir, direction):
        """处理文件缺失情况"""
        source_path = os.path.join(source_dir, rel_path)
        target_path = os.path.join(target_dir, rel_path)
        
        if os.path.exists(source_path):
            if os.path.isdir(source_path):
                self.operations.append(('mkdir', target_path, None))
            else:
                self.operations.append(('copy', source_path, target_path))
            logging.info(f"需要同步 {direction} {rel_path}")
    
    def execute_sync(self, dry_run=False):
        """执行同步操作"""
        logging.info(f"开始同步操作（{'模拟运行' if dry_run else '实际执行'}）")
        total_ops = len(self.operations)
        processed = 0
        
        for op in self.operations:
            processed += 1
            try:
                if op[0] == 'copy':
                    if dry_run:
                        logging.info(f"[模拟] 复制 {os.path.basename(op[1])} → {op[2]}")
                        continue
                    os.makedirs(os.path.dirname(op[2]), exist_ok=True)
                    shutil.copy2(op[1], op[2])
                    logging.info(f"已复制 {os.path.basename(op[1])} → {op[2]}")
                    
                elif op[0] == 'mkdir':
                    if dry_run:
                        logging.info(f"[模拟] 创建目录 {os.path.basename(op[1])}")
                        continue
                    os.makedirs(op[1], exist_ok=True)
                    logging.info(f"已创建目录 {os.path.basename(op[1])}")
                    
                elif op[0] == 'update':
                    if dry_run:
                        logging.info(f"[模拟] 更新 {os.path.basename(op[1])}")
                        continue
                    shutil.copy2(op[1], op[2])
                    logging.info(f"已更新 {os.path.basename(op[1])}")
                    
                elif op[0] == 'conflict':
                    if dry_run:
                        logging.warning(f"[模拟] 冲突文件 {os.path.basename(op[2])}")
                        continue
                    shutil.copy2(op[1], op[2])
                    logging.warning(f"已创建冲突副本 {os.path.basename(op[2])}")
                    
                # 更新进度
                logging.info(f"进度: {processed}/{total_ops} ({processed/total_ops:.1%})")
                
            except PermissionError as e:
                logging.error(f"权限不足: {os.path.basename(op[1])}")
                self._handle_permission_error(op)
            except FileNotFoundError as e:
                logging.error(f"文件不存在: {os.path.basename(op[1])}")
            except shutil.SameFileError:
                logging.info(f"文件未变化: {os.path.basename(op[1])}")
        
        logging.info(f"同步完成，共处理 {total_ops} 项操作")

    def _resolve_manual_conflict(self, rel_path):
        """处理手动解决冲突"""
        src_path = os.path.join(self.src, rel_path)
        dst_path = os.path.join(self.dst, rel_path)
        
        choice = messagebox.askyesnocancel(
            "文件冲突",
            f"请选择如何处理冲突文件: {rel_path}\n"
            "是(Y)用源文件覆盖\n否(N)保留目标文件\n取消(C)跳过"
        )
        
        if choice is True:
            self.operations.append(('update', src_path, dst_path))
        elif choice is False:
            self.operations.append(('update', dst_path, src_path))

    def _handle_permission_error(self, op):
        """处理权限错误"""
        try:
            os.chmod(op[1], 0o644)
            logging.info(f"已尝试修复权限: {op[1]}")
        except Exception as e:
            logging.error(f"权限修复失败: {str(e)}")

    def validate_path(self, path):
        """增强路径验证逻辑"""
        logging.debug(f"开始验证路径: {path}")
        if not os.path.exists(path):
            logging.error(f"路径不存在: {path}")
            raise FileNotFoundError(f"路径不存在: {path}")
        if not os.path.isdir(path):
            logging.error(f"不是目录: {path}")
            raise NotADirectoryError(f"不是目录: {path}")
        if not os.access(path, os.R_OK):
            logging.error(f"目录不可读: {path}")
            raise PermissionError(f"目录不可读: {path}")
        abs_path = os.path.abspath(path)
        logging.info(f"验证通过的路径: {abs_path}")
        return abs_path

    def _files_differ(self, file1, file2):
        """精确比较两个文件是否不同"""
        if os.path.getsize(file1) != os.path.getsize(file2):
            return True
        if os.path.getmtime(file1) != os.path.getmtime(file2):
            return True
        return self.calculate_hash(file1) != self.calculate_hash(file2)

    def _calculate_differences(self, src_tree, dst_tree, base1, base2):
        """计算差异数量"""
        diff_count = 0
        if not src_tree and not dst_tree:
            return 0
        all_dirs = set(src_tree.keys()) | set(dst_tree.keys())
        for d in all_dirs:
            src_files = src_tree.get(d, {}).get('files', set())
            dst_files = dst_tree.get(d, {}).get('files', set())
            diff_count += len([
                f for f in src_files | dst_files
                if self._get_file_status(os.path.join(d, f), base1, base2) != 'unchanged'
            ])
        return diff_count

class SyncGUI(tk.Tk):
    """文件同步工具图形界面"""
    
    def __init__(self):
        super().__init__()
        self.title("文件同步工具")
        self.geometry("800x600")
        self.syncer = None
        self.running = False
        self.log_queue = queue.Queue()
        self.after(100, self._process_log_queue)
        self._setup_ui()
        
    def _setup_ui(self):
        """初始化用户界面"""
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 路径选择部分
        path_frame = ttk.LabelFrame(main_frame, text="同步目录设置")
        path_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(path_frame, text="源目录:").grid(row=0, column=0, padx=5)
        self.src_entry = ttk.Entry(path_frame, width=50)
        self.src_entry.grid(row=0, column=1, padx=5)
        ttk.Button(path_frame, text="浏览...", command=self._browse_src).grid(row=0, column=2)
        
        ttk.Label(path_frame, text="目标目录:").grid(row=1, column=0, padx=5)
        self.dst_entry = ttk.Entry(path_frame, width=50)
        self.dst_entry.grid(row=1, column=1, padx=5)
        ttk.Button(path_frame, text="浏览...", command=self._browse_dst).grid(row=1, column=2)
        
        # 在路径选择部分下方添加设置面板
        settings_frame = ttk.LabelFrame(main_frame, text="同步设置")
        settings_frame.pack(fill=tk.X, pady=5)
        
        # 阈值设置组件
        ttk.Label(settings_frame, text="时间阈值(秒):").grid(row=0, column=0, padx=5)
        self.threshold_entry = ttk.Entry(settings_frame, width=8)
        self.threshold_entry.insert(0, "60")  # 默认推荐值
        self.threshold_entry.grid(row=0, column=1, padx=5, sticky=tk.W)
        
        # 添加说明标签
        help_icon = ttk.Label(settings_frame, text="ⓘ", foreground="blue")
        help_icon.grid(row=0, column=2, padx=5)
        help_icon.bind("<Enter>", self._show_threshold_help)
        help_icon.bind("<Leave>", self._hide_threshold_help)
        
        # 控制面板
        control_frame = ttk.LabelFrame(main_frame, text="操作控制")
        control_frame.pack(fill=tk.X, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="开始同步", command=self.start_sync)
        self.start_btn.pack(side=tk.LEFT, padx=10)
        
        ttk.Button(control_frame, text="模拟运行", command=self.dry_run).pack(side=tk.LEFT, padx=10)
        ttk.Button(control_frame, text="比较目录", command=self.compare_directories).pack(side=tk.LEFT, padx=10)
        ttk.Button(control_frame, text="停止", command=self.stop_sync).pack(side=tk.LEFT, padx=10)
        
        # 在控制面板添加退出按钮
        ttk.Button(control_frame, text="退出", command=self._safe_exit).pack(side=tk.RIGHT, padx=10)
        
        # 添加进度条
        self.progress = ttk.Progressbar(control_frame, mode='determinate')
        self.progress.pack(side=tk.LEFT, padx=10)
        
        # 添加进度详情标签
        self.progress_detail = ttk.Label(control_frame, text="0/0 文件已处理")
        self.progress_detail.pack(side=tk.LEFT, padx=10)
        
        # 日志显示
        log_frame = ttk.LabelFrame(main_frame, text="同步日志")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = tk.Text(log_frame, wrap=tk.WORD)
        scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 状态栏
        self.status = ttk.Label(self, text="就绪", relief=tk.SUNKEN)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)
        
    def _browse_src(self):
        path = filedialog.askdirectory()
        if path:
            path = os.path.normpath(path)  # 规范化路径格式
            self.src_entry.delete(0, tk.END)
            self.src_entry.insert(0, path)
            
    def _browse_dst(self):
        path = filedialog.askdirectory()
        if path:
            self.dst_entry.delete(0, tk.END)
            self.dst_entry.insert(0, path)
            
    def start_sync(self):
        """启动同步线程"""
        if self.running:
            return
            
        src = self.src_entry.get()
        dst = self.dst_entry.get()
        
        # 增强路径验证
        try:
            src = self._validate_path(src)
            dst = self._validate_path(dst)
        except Exception as e:
            messagebox.showerror("路径错误", str(e))
            return
            
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.status.config(text="正在同步...")
        self.progress['value'] = 0  # 重置进度条
        
        # 在创建syncer时传入阈值
        threshold = self._get_threshold()
        self.syncer = FileSynchronizer(
            src, dst,
            time_threshold=threshold,
            conflict_strategy='timestamp'
        )
        self.syncer.gui = self  # 建立双向引用
        self.log_text.delete(1.0, tk.END)
        
        # 初始化进度条
        self.progress['maximum'] = len(self.syncer.operations)
        
        # 启动后台线程
        try:
            Thread(target=self._run_sync, daemon=True).start()
        except Exception as e:
            self.log(f"无法启动线程: {str(e)}", level="ERROR")
            self.running = False
            self.start_btn.config(state=tk.NORMAL)
            
    def dry_run(self):
        """模拟运行"""
        if self.running:
            return
            
        src = self.src_entry.get()
        dst = self.dst_entry.get()
        
        if not os.path.isdir(src) or not os.path.isdir(dst):
            messagebox.showerror("错误", "请选择有效的目录路径")
            return
            
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.status.config(text="模拟运行中...")
        
        self.syncer = FileSynchronizer(src, dst)
        self.syncer.gui = self  # 建立双向引用
        self.log_text.delete(1.0, tk.END)
        
        # 初始化进度条
        self.progress['maximum'] = len(self.syncer.operations)
        self.progress['value'] = 0
        
        # 启动后台线程
        Thread(target=self._run_dry, daemon=True).start()
        
    def stop_sync(self):
        """停止同步"""
        self.running = False
        self.status.config(text="操作已停止")
        
    def _run_sync(self):
        """实际执行同步"""
        try:
            self.log("正在初始化同步器...", level="INFO")
            self.syncer.compare_and_index_files()
            self.log("开始执行同步操作...", level="INFO")
            self.syncer.execute_sync()
        except Exception as e:
            self.log(f"同步错误: {str(e)}", level="ERROR")
            messagebox.showerror("同步错误", f"操作失败: {str(e)}")
        finally:
            self.running = False
            self.start_btn.config(state=tk.NORMAL)
            self.status.config(text="同步完成")
            self.progress['value'] = self.progress['maximum']  # 完成进度条
            
    def _run_dry(self):
        """执行模拟运行"""
        try:
            self.syncer.compare_and_index_files()
            self.syncer.execute_sync(dry_run=True)
        except Exception as e:
            self.log(f"错误: {str(e)}", level="ERROR")
        finally:
            self.running = False
            self.start_btn.config(state=tk.NORMAL)
            self.status.config(text="模拟运行完成")
            
    def log(self, message, level="INFO"):
        """线程安全的日志记录"""
        self.log_queue.put((message, level))

    def _process_log_queue(self):
        while not self.log_queue.empty():
            msg, level = self.log_queue.get_nowait()
            self._safe_log(msg, level)
        self.after(100, self._process_log_queue)

    def _safe_log(self, message, level):
        """实际更新UI的代码..."""
        color_map = {
            "INFO": "black",
            "WARNING": "orange",
            "ERROR": "red"
        }
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.tag_add(level, "end-2l linestart", "end-2l lineend")
        self.log_text.tag_config(level, foreground=color_map.get(level, "black"))
        self.log_text.see(tk.END)
        self.update_idletasks()

    def _show_threshold_help(self, event):
        """显示阈值帮助提示"""
        help_text = (
            "时间阈值说明：\n"
            "当文件修改时间差超过此值时\n"
            "自动选择较新版本覆盖旧文件\n"
            "推荐值：30-120秒\n"
            "设为0将禁用时间戳策略"
        )
        self.help_tip = tk.Toplevel()
        self.help_tip.wm_overrideredirect(True)
        x = event.widget.winfo_rootx() + 20
        y = event.widget.winfo_rooty() + 20
        self.help_tip.geometry(f"+{x}+{y}")
        ttk.Label(self.help_tip, text=help_text, background="#FFFFE0", 
                relief="solid", borderwidth=1).pack(padx=5, pady=5)

    def _hide_threshold_help(self, event):
        if hasattr(self, 'help_tip'):
            self.help_tip.destroy()

    def _get_threshold(self):
        """安全获取阈值设置"""
        try:
            threshold = int(self.threshold_entry.get())
            return max(0, threshold)  # 确保非负
        except ValueError:
            messagebox.showerror("输入错误", "请输入有效的整数阈值")
            return 60  # 返回默认值

    def _safe_exit(self):
        """安全退出程序"""
        if self.running:
            if messagebox.askokcancel("退出", "同步正在进行中，确定要退出吗？"):
                self.destroy()
        else:
            self.destroy()

    def destroy(self):
        """重写销毁方法确保资源释放"""
        if self.syncer:
            self.syncer = None
        super().destroy()

    def _estimate_file_count(self):
        # 实现文件数量预估逻辑
        return 100  # 示例值

    def update_progress(self, current, total):
        self.progress['value'] = current
        self.progress['maximum'] = total
        self.progress_detail.config(text=f"{current}/{total} 文件已处理")

    def _validate_path(self, path):
        """增强路径验证"""
        if not path:
            raise ValueError("路径不能为空")
        if not os.path.exists(path):
            raise FileNotFoundError(f"路径不存在: {path}")
        if not os.path.isdir(path):
            raise NotADirectoryError(f"不是有效目录: {path}")
        if not os.access(path, os.R_OK):
            raise PermissionError(f"目录不可读: {path}")
        return os.path.abspath(path)

    def compare_directories(self):
        """比较目录内容"""
        try:
            src = self._validate_path(self.src_entry.get())
            dst = self._validate_path(self.dst_entry.get())
        except Exception as e:
            messagebox.showerror("错误", str(e))
            return
        
        # 创建比较窗口
        compare_win = tk.Toplevel(self)
        compare_win.title("目录内容比较")
        compare_win.geometry("1024x768")
        compare_win.minsize(800, 600)
        
        # 主容器
        main_frame = ttk.Frame(compare_win)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 控制面板
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)
        
        # 使用独立容器存放按钮防止被销毁
        btn_container = ttk.Frame(control_frame)
        btn_container.pack(side=tk.TOP, fill=tk.X, anchor='nw')
        
        self.refresh_btn = ttk.Button(btn_container, text="刷新", 
                    command=lambda: self._refresh_comparison(content_pane, src, dst))
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_container, text="关闭", command=compare_win.destroy).pack(side=tk.RIGHT, padx=5)
        
        # 内容面板
        content_pane = ttk.Frame(main_frame)
        content_pane.pack(fill=tk.BOTH, expand=True)
        self._build_comparison_content(content_pane, src, dst)

    def _refresh_comparison(self, parent, src, dst):
        """刷新比较内容"""
        # 清除旧内容
        for widget in parent.winfo_children():
            widget.destroy()  # 只清除内容面板
        self._build_comparison_content(parent, src, dst)
        parent.update_idletasks()  # 强制立即更新界面

    def _build_comparison_content(self, parent, src, dst):
        """构建比较内容"""
        # 双栏布局
        pane = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        pane.pack(fill=tk.BOTH, expand=True)
        
        # 源目录列
        src_frame = ttk.LabelFrame(pane, text=f"源目录 [{src}]")
        self._build_comparison_tree(src_frame, src, dst)
        pane.add(src_frame)
        
        # 目标目录列
        dst_frame = ttk.LabelFrame(pane, text=f"目标目录 [{dst}]")
        self._build_comparison_tree(dst_frame, dst, src)
        pane.add(dst_frame)
        
        # 差异统计
        diff_count = self._calculate_differences(
            self._scan_for_comparison(src),
            self._scan_for_comparison(dst),
            src,
            dst
        )
        self.diff_label = ttk.Label(parent, text=f"发现 {diff_count} 处差异")
        self.diff_label.config(text=f"最后更新: {datetime.now().strftime('%H:%M:%S')} | 差异数: {diff_count}")
        self.diff_label.pack(pady=5)

    def _build_comparison_tree(self, parent, base_path, other_base):
        """构建带颜色标记的目录树"""
        # 先清除旧内容
        for widget in parent.winfo_children():
            widget.destroy()
        parent.update_idletasks()  # 强制清除残留组件
        
        if not os.path.exists(base_path):
            return ttk.Label(parent, text="目录不存在").pack()
        
        tree = ttk.Treeview(parent, columns=('type', 'size', 'mtime', 'status'), 
                          show='tree headings', style='Custom.Treeview')
        
        # 列配置
        tree.column('#0', width=250, anchor='w')
        tree.column('type', width=80, anchor='center')
        tree.column('size', width=100, anchor='e')
        tree.column('mtime', width=150, anchor='center')
        tree.column('status', width=80, anchor='center')
        
        tree.heading('#0', text='名称', anchor='w')
        tree.heading('type', text='类型')
        tree.heading('size', text='大小')
        tree.heading('mtime', text='修改时间')
        tree.heading('status', text='状态')
        
        # 滚动条
        vsb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # 布局
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        tree.pack(fill=tk.BOTH, expand=True)
        
        # 样式
        tree.tag_configure('new', foreground='red')
        tree.tag_configure('deleted', foreground='red')
        tree.tag_configure('modified', foreground='red')
        tree.tag_configure('unchanged', foreground='green')
        
        # 加载数据
        file_tree = self._scan_for_comparison(base_path) if os.path.exists(base_path) else {}
        other_tree = self._scan_for_comparison(other_base)
        all_dirs = set(file_tree.keys()) | set(other_tree.keys())
        
        for rel_path in sorted(all_dirs):
            # 处理目录元数据
            full_path = os.path.join(base_path, rel_path)
            dir_status = self._get_directory_status(rel_path, base_path, other_base)
            
            if not os.path.exists(base_path):
                continue  # 跳过不存在的目录
            
            # 获取目标目录元数据
            target_dir_path = os.path.join(other_base, rel_path)
            if not os.path.exists(target_dir_path) or not os.path.exists(other_base):
                target_dir_path = full_path
            target_dir_info = self._get_file_metadata(target_dir_path)
            
            dir_info = self._get_file_metadata(full_path)
            display_mtime = target_dir_info.get('mtime', dir_info['mtime'])
            
            # 插入目录节点
            tree.insert('', 'end', rel_path,
                        text=os.path.basename(rel_path) if rel_path != '.' else os.path.basename(base_path),
                        values=(
                            dir_info['type'],
                            dir_info['size'],
                            display_mtime,
                            dir_status
                        ),
                        tags=(dir_status,),
                        open=True)
            
            # 处理文件
            src_files = file_tree.get(rel_path, {}).get('files', set())
            dst_files = other_tree.get(rel_path, {}).get('files', set())
            
            if not os.path.exists(base_path):
                src_files = set()  # 源目录不存在时清空文件列表
            
            # 显示源文件
            for f in src_files:
                file_path = os.path.join(base_path, rel_path, f)
                file_status = self._get_file_status(os.path.join(rel_path, f), base_path, other_base)
                file_info = self._get_file_metadata(file_path)
                
                # 获取目标文件元数据
                target_file_path = os.path.join(other_base, rel_path, f)
                if not os.path.exists(target_file_path) or not os.path.exists(other_base):
                    target_file_path = file_path
                target_file_info = self._get_file_metadata(target_file_path)
                display_file_mtime = target_file_info.get('mtime', file_info['mtime'])
                
                tree.insert(rel_path, 'end',
                            text=f,
                            values=(
                                file_info['type'],
                                file_info['size'],
                                display_file_mtime if os.path.exists(other_base) else file_info['mtime'],
                                file_status
                            ),
                            tags=(file_status,))
            
            # 显示目标目录额外文件
            if not os.path.exists(other_base):
                continue  # 目标目录不存在时不显示额外文件

            for f in dst_files - src_files:
                file_path = os.path.join(other_base, rel_path, f)
                file_info = self._get_file_metadata(file_path)
                tree.insert(rel_path, 'end',
                            text=f,
                            values=(
                                file_info['type'],
                                file_info['size'],
                                file_info['mtime'],
                                'new'
                            ),
                            tags=('new',))
        
        return tree

    def _scan_for_comparison(self, path):
        """生成目录结构树"""
        file_tree = {}
        try:
            if not os.path.exists(path):
                return file_tree
            for root, dirs, files in os.walk(path):
                rel_path = os.path.relpath(root, path)
                file_tree[rel_path] = {
                    'files': set(files),
                    'dirs': set(dirs)
                }
        except Exception as e:
            self.log(f"目录扫描错误: {str(e)}", "ERROR")
        return file_tree

    def _get_directory_status(self, rel_path, base1, base2):
        """获取目录状态"""
        full_path1 = os.path.join(base1, rel_path)
        full_path2 = os.path.join(base2, rel_path)
        
        exists1 = os.path.exists(full_path1)
        exists2 = os.path.exists(full_path2)
        
        if not exists1 and not exists2:
            return 'deleted'
        if exists1 and not exists2:
            return 'new'
        if not exists1 and exists2:
            return 'deleted'
        
        # 检查子文件是否有差异
        src_tree = self._scan_for_comparison(full_path1)
        dst_tree = self._scan_for_comparison(full_path2)
        if src_tree != dst_tree:
            return 'modified'
        return 'unchanged'

    def _get_file_status(self, rel_path, base1, base2):
        """获取文件状态"""
        if not os.path.exists(base2):
            return 'new'  # 当目标目录不存在时，所有文件标记为新增
        file1 = os.path.join(base1, rel_path)
        file2 = os.path.join(base2, rel_path)
        
        if not os.path.exists(file2):
            return 'new'
        if not os.path.exists(file1):
            return 'deleted'
        if FileSynchronizer(file1, file2)._files_differ(file1, file2):
            return 'modified'
        return 'unchanged'

    def _get_file_metadata(self, path):
        """获取文件元数据"""
        try:
            if not os.path.exists(path):
                return {
                    'type': '未知',
                    'size': 'N/A',
                    'mtime': 'N/A'
                }
            stat = os.stat(path)
            return {
                'type': '目录' if os.path.isdir(path) else '文件',
                'size': self._format_size(stat.st_size),
                'mtime': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            self.log(f"获取元数据失败: {path} - {str(e)}", "ERROR")
            return {
                'type': '错误',
                'size': 'N/A',
                'mtime': 'N/A'
            }

    def _format_size(self, size):
        """格式化文件大小"""
        units = ['B', 'KB', 'MB', 'GB']
        index = 0
        while size >= 1024 and index < 3:
            size /= 1024
            index += 1
        return f"{size:.2f} {units[index]}"

    def _calculate_differences(self, src_tree, dst_tree, base1, base2):
        """计算差异数量"""
        diff_count = 0
        if not src_tree and not dst_tree:
            return 0
        all_dirs = set(src_tree.keys()) | set(dst_tree.keys())
        for d in all_dirs:
            src_files = src_tree.get(d, {}).get('files', set())
            dst_files = dst_tree.get(d, {}).get('files', set())
            diff_count += len([
                f for f in src_files | dst_files
                if self._get_file_status(os.path.join(d, f), base1, base2) != 'unchanged'
            ])
        return diff_count

class SyncError(Exception):
    """自定义同步异常基类"""

def create_parser() -> argparse.ArgumentParser:
    """创建并配置命令行参数解析器"""
    parser = argparse.ArgumentParser(
        prog="sync_tool",
        description="文件同步工具",  # 添加更清晰的程序描述
        formatter_class=argparse.ArgumentDefaultsHelpFormatter  # 显示默认值
    )
    
    # 建议将参数分组以提升可读性
    io_group = parser.add_argument_group("输入输出")
    io_group.add_argument(
        "-s", "--source",
        type=Path,  # 使用Path类型自动处理路径
        required=True,
        help="源目录路径"
    )
    io_group.add_argument(
        "-d", "--dest",
        type=Path,
        required=True,
        help="目标目录路径"
    )

    # 添加参数验证逻辑
    def validate_threads(value):
        ivalue = int(value)
        if ivalue <= 0 or ivalue > 32:
            raise argparse.ArgumentTypeError("线程数必须在1-32之间")
        return ivalue

    perf_group = parser.add_argument_group("性能设置")
    perf_group.add_argument(
        "-t", "--threads",
        type=validate_threads,  # 添加参数验证
        default=4,
        help="并发线程数 (1-32)"
    )

    # 互斥参数处理
    conflict_group = parser.add_mutually_exclusive_group()
    conflict_group.add_argument(
        "--force",
        action="store_true",
        help="强制覆盖已存在文件"
    )
    conflict_group.add_argument(
        "--dry-run",
        action="store_true",
        help="试运行模式（不实际执行操作）"
    )

    # 添加版本信息
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="%(prog)s 1.0.0"
    )
    
    return parser

# 新增参数后处理验证函数
def validate_args(args: argparse.Namespace) -> Optional[str]:
    """验证参数逻辑关系，返回错误信息或None"""
    if not args.source.exists():
        return f"源目录不存在: {args.source}"
    if not args.source.is_dir():
        return f"源路径不是目录: {args.source}"
    if args.dest.exists() and not args.dest.is_dir():
        return f"目标路径不是目录: {args.dest}"
    return None

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    syncer = FileSynchronizer(
        args.src,
        args.dst,
        log_file=args.log,
        conflict_suffix=args.conflict_suffix
    )
    
    try:
        logging.info("开始扫描目录...")
        syncer.compare_and_index_files()
        syncer.execute_sync(dry_run=args.dry_run)
    except KeyboardInterrupt:
        logging.warning("用户中断操作")
    except Exception as e:
        logging.error(f"严重错误: {str(e)}", exc_info=True)

if __name__ == "__main__":
    gui = SyncGUI()
    gui.mainloop() 