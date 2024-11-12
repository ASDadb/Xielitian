# 文件 1: main.py
if __name__ == "__main__":
    import scan_functions
    import file_manager
    import tkinter as tk
    from tkinter import messagebox
    import threading
    import time
    import queue

    # 创建GUI窗口
    app = tk.Tk()
    app.title("Anti-Malware Scanner")

    # 定义当前目录，用于删除操作
    current_directory = None
    is_scanning = False
    scanned_bytes = 0
    total_files = 0  # 新增：文件总数
    start_time = 0
    byte_queue = queue.Queue()  # 使用队列在线程间传递扫描的字节数
    file_count_queue = queue.Queue()  # 使用队列在线程间传递文件数
    scan_results = []  # 全局变量，用于存储扫描结果

    def scan_selected_directory():
        global current_directory, is_scanning, scanned_bytes, total_files, start_time
        # 让用户选择文件夹并进行扫描
        current_directory = file_manager.select_directory()
        if current_directory:
            # 重置扫描状态
            scanned_bytes = 0
            total_files = 0
            is_scanning = True
            start_time = time.time()  # 在扫描开始时记录时间
            speed_label.config(text="Scanning speed: 0 bytes/sec")
            elapsed_time_label.config(text="Elapsed time: 0 seconds")
            total_files_label.config(text="Total Files Scanned: 0")
            total_size_label.config(text="Total Size Scanned: 0 bytes")

            # 启动扫描线程
            scan_thread = threading.Thread(target=scan_files_thread)
            scan_thread.start()

            # 启动速度更新
            update_speed()

    def update_scanned_bytes():
        """
        从队列中取出字节数并进行累加
        Update the scanned bytes and total files from the queue
        """
        global scanned_bytes, total_files
        while not byte_queue.empty():
            file_size = byte_queue.get()
            scanned_bytes += file_size
        while not file_count_queue.empty():
            file_count_queue.get()
            total_files += 1

    def scan_files_thread():
        global is_scanning, scan_results
        # 执行扫描操作并实时更新扫描字节数
        scan_results = scan_functions.scan_files_with_progress(current_directory, byte_queue, file_count_queue)

        # 扫描完成后更新UI
        is_scanning = False
        app.after(0, update_scan_results)  # 使用 app.after() 确保 UI 更新在主线程中进行

    def update_speed():
        global start_time
        if is_scanning:
            # 更新扫描的字节数和文件数量
            update_scanned_bytes()

            # 计算扫描速度和时间
            current_time = time.time()
            elapsed_time = current_time - start_time if start_time > 0 else 0

            # 确保有足够的时间来计算速度
            if elapsed_time > 0:
                speed = scanned_bytes / elapsed_time
                speed_label.config(text=f"Scanning speed: {speed:.2f} bytes/sec")
            else:
                speed_label.config(text="Scanning speed: 0 bytes/sec")

            # 更新 current_time 和 elapsed_time 的标签
            current_time_label.config(text=f"Current time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time))}")
            elapsed_time_label.config(text=f"Elapsed time: {elapsed_time:.2f} seconds")

            # 更新文件总数和总大小的标签  Updated labels for total number of files and total size
            total_files_label.config (text=f"Total Files Scanned: {total_files}")
            total_size_label.config(text=f"Total Size Scanned: {scanned_bytes} bytes")

        # 每秒更新一次扫描速度
        app.after(1000, update_speed)

    def update_scan_results():
        """
        更新GUI中显示的扫描结果
        Update the scan results displayed in GUI
        """
        # 清空文本框
        text_widget.delete("1.0", tk.END)
        for result in scan_results:
            file_name, is_malware = result
            status = "Malware Detected" if is_malware else "No Malware"
            display_text = f"{file_name}: {status}\n"

            if is_malware:
                text_widget.insert(tk.END, display_text, "malware")
            else:
                text_widget.insert(tk.END, display_text)

    def delete_selected_file():
        try:
            # 获取当前选中的文本行
            selected_index = text_widget.index(tk.SEL_FIRST).split(".")[0]
            selected_line = text_widget.get(f"{selected_index}.0", f"{selected_index}.end").strip()

            if selected_line:
                file_name = selected_line.split(":")[0]
                file_path = file_manager.get_file_path(current_directory, file_name)

                # 删除选中文件
                if file_manager.delete_file(file_path):
                    text_widget.delete(f"{selected_index}.0", f"{selected_index}.end")
                    messagebox.showinfo("Success", f"File {file_name} deleted successfully!")
                else:
                    messagebox.showerror("Error", f"Failed to delete {file_name}")
            else:
                messagebox.showwarning("No Selection", "Please select a file to delete.")

        except tk.TclError:
            messagebox.showwarning("No Selection", "Please select a file to delete.")

    # GUI界面组件
    scan_button = tk.Button(app, text="Scan Directory", command=scan_selected_directory)
    scan_button.pack(pady=10)

    delete_button = tk.Button(app, text="Delete Selected File", command=delete_selected_file)
    delete_button.pack(pady=10)

    # 使用Text组件来替换Listbox
    text_widget = tk.Text(app, width=80, height=20)
    text_widget.pack(pady=10)

    # 定义一个标签，用于恶意软件的红色显示
    text_widget.tag_config("malware", foreground="red")

    # 添加速度标签
    speed_label = tk.Label(app, text="Scanning speed: 0 bytes/sec")
    speed_label.pack(pady=5)

    # 添加当前时间标签
    current_time_label = tk.Label(app, text="Current time: N/A")
    current_time_label.pack(pady=5)

    # 添加已用时间标签
    elapsed_time_label = tk.Label(app, text="Elapsed time: 0 seconds")
    elapsed_time_label.pack(pady=5)

    # 添加文件总数标签
    total_files_label = tk.Label(app, text="Total Files Scanned: 0")
    total_files_label.pack(pady=5)

    # 添加总大小标签
    total_size_label = tk.Label(app, text="Total Size Scanned: 0 bytes")
    total_size_label.pack(pady=5)

    app.mainloop()

