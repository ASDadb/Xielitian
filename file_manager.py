import os
import tkinter.filedialog as filedialog

def select_directory():
    """
    选择目录
    Select directory.
    """
    return filedialog.askdirectory()

def get_file_path(current_directory, file_name):
    """
    获取文件的完整路径。
    Get the full path of a file.
    """
    return os.path.join(current_directory, file_name)

def delete_file(file_path):
    """
    删除指定文件。
    Delete the specified file.
    """
    try:
        os.remove(file_path)
        return True
    except Exception as e:
        print(f"Failed to delete file {file_path}: {str(e)}")