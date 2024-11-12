# 文件 2: scan_functions.py
import os
import time

def check_pe_file(file_content, signatures):
    """
    检查PE文件的特征码。
    Check PE file for signatures.

    :param file_content: 文件内容 / File content
    :param signatures: 特征库 / Signatures
    :return: 是否发现恶意软件特征码 / Whether malware signature is found
    """
    for signature in signatures.values():
        if signature in file_content:
            return True
    return False

# 特征库，存储特征码
# Signature library to store malware signatures
signatures = {
    'malware1': b'\x12\x34\x56\x78',  # 特征码1 / Signature 1
    'malware2': b'\x92\x22\x38\x56',  # 特征码2 / Signature 2
    'malware3': b'\x78\x56\x34\x12',  # 特征码3 / Signature 3
    'malware4': b'\x56\x78\x90\x12'  # 特征码4 / Signature 4
}

def scan_files_with_progress(directory, byte_queue, file_count_queue):
    """
    扫描指定目录下的文件并报告进度。
    Scan files in the specified directory and report progress.

    :param directory: 要扫描的目录 / Directory to scan
    :param byte_queue: 用于传递字节数的队列 / Queue to pass bytes count
    :param file_count_queue: 用于传递文件数的队列 / Queue to pass file count
    :return: 扫描结果列表 / List of scan results
    """
    malware_found_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                # 检查文件大小，这里以10MB为例，可以根据需要调整
                # Check file size, e.g. skip files larger than 10MB
                file_size = os.path.getsize(file_path)

                if file_size > 10 * 1024 * 1024:
                    continue

                # 读取文件内容
                # Read file content
                with open(file_path, 'rb') as f:
                    file_content = f.read()

                # 更新扫描的字节数和文件数到队列
                # Update scanned bytes and file count to queue
                byte_queue.put(file_size)
                file_count_queue.put(1)

                # 模拟扫描耗时，用于测试
                time.sleep(0.1)  # 增加0.1秒的延时，以便更容易看到扫描速度的变化

                # 检查文件类型，这里以PE文件为例
                # Check file type, e.g. PE files
                if file.endswith('.exe') or file.endswith('.dll'):
                    if check_pe_file(file_content, signatures):
                        malware_found_files.append((file, True))  # 恶意软件 / Malware detected
                    else:
                        malware_found_files.append((file, False))  # 无恶意软件 / No malware
                else:
                    malware_found_files.append((file, False))  # 非PE文件 / Not a PE file

            except Exception as e:
                print(f"An error occurred while scanning file {file_path}: {str(e)}")

    return malware_found_files
