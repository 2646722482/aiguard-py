from setuptools import setup, find_packages

setup(
    name="aiguard",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "openai>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "aiguard=aiguard.cli:main",
        ],
    },
    author="你的名字",
    author_email="你的邮箱",
    description="AI驱动的Python代码安全审计工具",
    long_description="用AI检测Python代码中的安全漏洞，给出修复建议",
    long_description_content_type="text/markdown",
    url="https://github.com/你的用户名/aiguard",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)