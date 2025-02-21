import pytest
from pathlib import Path
from sync_tool.core.synchronizer import FileSynchronizer
from sync_tool.utils.logger import setup_logger

@pytest.fixture
def test_syncer(tmp_path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    return FileSynchronizer(src, dst, setup_logger())

def test_basic_sync(test_syncer):
    # 创建测试文件
    (test_syncer.src / "test.txt").write_text("content")
    
    test_syncer.compare_and_index_files()
    assert len(test_syncer.operations) == 1
    assert test_syncer.operations[0][0] == 'copy'

def test_empty_sync(test_syncer):
    test_syncer.compare_and_index_files()
    assert len(test_syncer.operations) == 0

if __name__ == "__main__":
    pytest.main() 