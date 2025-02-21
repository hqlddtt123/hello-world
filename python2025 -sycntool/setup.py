from setuptools import setup, find_packages

setup(
    name='sync_tool',
    version='1.1.0',
    packages=find_packages(),
    install_requires=[
        'xxhash>=3.0.0',
        'tkintertable>=1.3',
        # 保持必要依赖
    ],
    entry_points={
        'console_scripts': [
            'sync-tool=sync_tool.cli.parser:main',  # 确保parser.py有main函数
            'sync-gui=sync_tool.ui.gui:main'       # 正确指向GUI入口
        ]
    }
) 