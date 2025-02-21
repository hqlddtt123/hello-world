import argparse
from pathlib import Path
import logging
from ..core.synchronizer import FileSynchronizer
from ..utils.logger import setup_logger
from ..cli.parser import create_parser, validate_args
from ..core.exceptions import SyncError

def main():
    logger = setup_logger()
    parser = create_parser()
    args = parser.parse_args()
    
    # 参数验证
    if error := validate_args(args):
        logger.error(error)
        return
    
    syncer = FileSynchronizer(
        src=args.source,
        dst=args.dest,
        logger=logger,
        conflict_strategy=args.conflict_strategy
    )
    
    try:
        syncer.compare_and_index_files()
        if args.dry_run:
            syncer.execute_sync(dry_run=True)
        else:
            syncer.execute_sync()
    except KeyboardInterrupt:
        logger.info("操作被用户中断")
    except SyncError as e:
        logger.error(f"同步错误: {str(e)}")

if __name__ == "__main__":
    main() 