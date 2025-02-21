from pathlib import Path
import configparser
from typing import Dict, Any

DEFAULT_CONFIG = {
    'general': {
        'threads': '4',
        'log_level': 'INFO'
    },
    'sync': {
        'time_threshold': '60',
        'conflict_strategy': 'timestamp'
    }
}

def load_config(config_path: Path = None) -> Dict[str, Any]:
    try:
        config = configparser.ConfigParser()
        config.read_dict(DEFAULT_CONFIG)
        
        if config_path and config_path.exists():
            config.read(config_path)
        
        return {
            'threads': config.getint('general', 'threads'),
            'log_level': config.get('general', 'log_level'),
            'time_threshold': config.getint('sync', 'time_threshold'),
            'conflict_strategy': config.get('sync', 'conflict_strategy')
        }
    except (configparser.Error, ValueError) as e:
        raise RuntimeError(f"配置文件加载失败: {str(e)}") from e 