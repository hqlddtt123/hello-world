#!/usr/bin/env python3
import os
import shutil
import logging
import argparse
import xxhash  # 更快的非加密哈希算法
from datetime import datetime
from threading import Thread
import queue
from concurrent.futures import ThreadPoolExecutor
from ..utils.logger import setup_logging

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

class FileSynchronizer:
    """高级文件同步工具"""
    
    def __init__(self, src, dst, log_file='sync.log', conflict_suffix='.conflict', conflict_strategy='timestamp', time_threshold=60, **kwargs):
        self.src = os.path.normpath(src)
        self.dst = os.path.normpath(dst)
        self.log_file = log_file
        self.conflict_suffix = conflict_suffix
        self.conflict_strategy = kwargs.get('conflict_strategy', 'timestamp')  # 支持 timestamp/hash/manual
        self.time_threshold = time_threshold
        self.logger = setup_logging()
        
        # 初始化文件索引
        self.src_index = {}
        self.dst_index = {}
        self.operations = []
        
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
                        self.logger.error(f"权限错误 {full_path}: {str(e)}", exc_info=True)
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
                        self.logger.info(f"[模拟] 复制 {os.path.basename(op[1])} → {op[2]}")
                        continue
                    os.makedirs(os.path.dirname(op[2]), exist_ok=True)
                    shutil.copy2(op[1], op[2])
                    
                elif op[0] == 'mkdir':
                    if dry_run:
                        self.logger.info(f"[模拟] 创建目录 {os.path.basename(op[1])}")
                        continue
                    os.makedirs(op[1], exist_ok=True)
                    self.logger.info(f"已创建目录 {os.path.basename(op[1])}")
                    
                elif op[0] == 'update':
                    if dry_run:
                        self.logger.info(f"[模拟] 更新 {os.path.basename(op[1])}")
                        continue
                    shutil.copy2(op[1], op[2])
                    self.logger.info(f"已更新 {os.path.basename(op[1])}")
                    
                elif op[0] == 'conflict':
                    if dry_run:
                        self.logger.warning(f"[模拟] 冲突文件 {os.path.basename(op[2])}")
                        continue
                    shutil.copy2(op[1], op[2])
                    self.logger.warning(f"已创建冲突副本 {os.path.basename(op[2])}")
                    
                # 更新进度
                if self.logger:
                    self.logger.info(f"同步完成，已处理 {processed} 项操作，共 {total_ops} 项操作")
                    
            except PermissionError as e:
                self._handle_permission_error(op)
            except FileNotFoundError as e:
                self.logger.error(f"文件不存在: {os.path.basename(op[1])}")
            except shutil.SameFileError:
                self.logger.info(f"文件未变化: {os.path.basename(op[1])}")
        
        self.logger.info(f"同步完成，共处理 {total_ops} 项操作")

    def _resolve_manual_conflict(self, rel_path):
        """处理手动解决冲突（CLI模式替代方案）"""
        src_path = os.path.join(self.src, rel_path)
        dst_path = os.path.join(self.dst, rel_path)
        
        # CLI模式下的替代方案
        print(f"检测到文件冲突: {rel_path}")
        choice = input("请选择操作 [Y]覆盖/[N]保留/[C]取消: ").lower()
        choice_map = {'y': True, 'n': False, 'c': None}
        return choice_map.get(choice, None)

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

class SyncError(Exception):
    """自定义同步异常基类"""

def main():
    parser = argparse.ArgumentParser(
        description='高级双向文件同步工具',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('src', help='源目录')
    parser.add_argument('dst', help='目标目录')
    parser.add_argument('-l', '--log', default='sync.log', help='日志文件路径')
    parser.add_argument('-n', '--dry-run', action='store_true', help='模拟运行')
    parser.add_argument('-c', '--conflict-suffix', default='.conflict', 
                       help='冲突文件后缀')
    
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
    main() 