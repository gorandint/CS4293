#!/usr/bin/env python3

import sys
from pathlib import Path

def hex_format(data: bytes) -> tuple[str, str]:
    """将字节数据转换为十六进制格式的字符串，返回十六进制部分和ASCII部分"""
    # hex_part = ' '.join(f'{b:02x}' for b in data)
    hex_part = ' '.join(f'{b1:02x}{b2:02x}' for b1, b2 in zip(data[::2], data[1::2]))
    # 补齐空格，确保对齐
    hex_part = f'{hex_part:<39}'  
    
    # ASCII部分：可打印字符显示原字符，不可打印字符显示'.'
    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
    return hex_part, ascii_part

def compare_files(file1: Path, file2: Path):
    """比较两个二进制文件，显示不同之处"""
    try:
        with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
            offset = 0
            while True:
                # 每次读取16字节
                chunk1 = f1.read(16)
                chunk2 = f2.read(16)
                
                # 如果两个文件都已读完，退出循环
                if not chunk1 and not chunk2:
                    break
                    
                # 补齐最后一块（如果不足16字节）
                chunk1 = chunk1.ljust(16, b'\0')
                chunk2 = chunk2.ljust(16, b'\0')
                
                # 如果两块内容不同，显示差异
                if chunk1 != chunk2:
                    hex1, ascii1 = hex_format(chunk1)
                    hex2, ascii2 = hex_format(chunk2)
                    
                    # 生成差异标记
                    marks = [' '] * 47
                    for i in range(16):
                        if i % 2 == 1:
                            pos = 5 * (i // 2) + 4
                        else:
                            pos = 5 * (i // 2) + 2
                        if i < len(chunk1) and i < len(chunk2) and chunk1[i] != chunk2[i]:
                            marks[pos] = '^'
                            marks[pos + 1] = '^'
                    
                    print(f'{offset:04x}: {hex1} |{ascii1}|')
                    print(f'{offset:04x}: {hex2} |{ascii2}|')
                    print(f'    {"".join(marks)}')
                    # print()
                
                offset += 16
                
                # 如果其中一个文件已读完，显示文件大小差异信息
                if bool(chunk1) != bool(chunk2):
                    print("Files have different sizes!")
                    break
                    
    except IOError as e:
        print(f"Error reading files: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    if len(sys.argv) != 3:
        print("Usage: bincompare.py <file1> <file2>", file=sys.stderr)
        sys.exit(1)
        
    file1 = Path(sys.argv[1])
    file2 = Path(sys.argv[2])
    
    if not file1.exists():
        print(f"Error: {file1} does not exist", file=sys.stderr)
        sys.exit(1)
    if not file2.exists():
        print(f"Error: {file2} does not exist", file=sys.stderr)
        sys.exit(1)
        
    compare_files(file1, file2)

if __name__ == '__main__':
    main()