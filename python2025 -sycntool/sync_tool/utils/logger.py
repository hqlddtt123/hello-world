import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

class ColoredFormatter(logging.Formatter):
    """带颜色的日志格式化器
    支持颜色：
    - 警告: 黄色
    - 错误: 红色 
    - 信息: 蓝色
    """
    COLORS = {
        'WARNING': '\033[93m',
        'ERROR': '\033[91m',
        'INFO': '\033[94m',
        'ENDC': '\033[0m'
    }
    
    def format(self, record):
        message = super().format(record)
        return f"{self.COLORS.get(record.levelname, '')}{message}{self.COLORS['ENDC']}"

def setup_logger(name: str = "FileSync") -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # 确保日志目录存在
    log_dir = Path.home() / ".sync_tool"
    log_dir.mkdir(exist_ok=True)
    
    file_handler = RotatingFileHandler(
        log_dir / "sync.log",
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredFormatter())
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger

def get_logger(name=None):
    """获取配置好的日志记录器"""
    return logging.getLogger(name or 'FileSync')
