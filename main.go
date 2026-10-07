// Package main 实现了一个基于 Go 的并发资产存活探测 CLI 工具。
// 主要功能：高并发资产扫描、HTTP 响应指纹提取（Server/Title）、CSV 结果落盘。
//
// ==========================================
// 【法律声明与免责】
// 本工具仅供网络安全学习、授权渗透测试及自有资产测绘使用。
// 严禁用于任何未授权的扫描、探测或攻击行为！
// 使用者需自行承担因不当使用而产生的所有法律责任。
// ==========================================

package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	input := flag.String("f", "urls.example.txt", "目标 URL 列表文件")
	timeout := flag.Int("t", 5, "单个请求超时秒数")
	concurrency := flag.Int("c", 5, "并发数 (同时工作的 worker 数量)")
	retries := flag.Int("r", 3, "失败重试次数")
	flag.Parse()

	file, err := os.Open(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "打开目标文件失败:", err)
		os.Exit(1)
	}
	defer file.Close()

	client := &http.Client{Timeout: time.Duration(*timeout) * time.Second}

	// ============初始化 CSV============
	// 1. 创建或覆盖 results.csv 文件
	outFile, err := os.Create("results.csv")
	if err != nil {
		fmt.Fprintln(os.Stderr, "创建结果文件失败：", err)
		os.Exit(1)
	}
	defer outFile.Close() //保证程序退出前关闭文件

	//2.创建CSV写入器并写入 UTF-8 BOM（防止Excel打开中文乱码）
	writer := csv.NewWriter(outFile)
	outFile.Write([]byte{0xEF, 0xBB, 0xBF}) // 写入 UTF-8 BOM，防止Excel打开中文乱码
	defer writer.Flush()                    // 保证程序退出前把缓冲区的数据刷入磁盘

	// 3. 写入表头（第一行）
	writer.Write([]string{"Target", "StatusCode", "Server", "Title", "Error"})

	// 4. 声明互斥锁，保护并发写入
	var mu sync.Mutex

	// ============ Worker Pool 并发控制 ============
	// 1. 创建任务 channel（生产者-消费者模型）
	jobs := make(chan string)
	var wg sync.WaitGroup

	// 2. 启动固定数量的 Worker 协程
	for i := 0; i < *concurrency; i++ {
		wg.Add(1) // 记录这个协程工作
		go func() {
			defer wg.Done() //释放

			// Worker 持续从 jobs channel 中读取任务，直到 channel 关闭且为空
			for target := range jobs {
				status, server, title, err := probe(client, target, *retries)

				//准备写入 CSV 的一行数据
				var record []string

				if err != nil {
					// 发生错误时，状态码记 0，错误信息记下来
					record = []string{target, "0", "-", "-", err.Error()}
					fmt.Printf("%-45s ERROR  %v\n", target, err)
				} else {
					// 正常时，Error 留空
					record = []string{target, fmt.Sprintf("%d", status), server, title, ""}
					// 格式化输出：目标 [状态码] [Server] [Title]
					// %-15s 代表占15个字符左对齐
					fmt.Printf("%-40s [%d] [%-15s] [%s]\n", target, status, server, title)
				}

				// 加锁写入 CSV，防止多协程并发写入导致数据错乱
				mu.Lock()
				writer.Write(record)
				// 注意：这里可以每写一行就 Flush 一次（确保实时落盘），
				// 但为了性能，通常等所有工人干完活，在 main 结束时统一 Flush。
				mu.Unlock()
			}
		}()
	}

	// 3. 主协程作为生产者，读取文件并向 jobs channel 发送任务
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target == "" {
			continue
		}
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "http://" + target
		}
		// 发送任务。当所有 Worker 都忙碌时，此处会阻塞，形成背压 (Backpressure) 机制
		jobs <- target
	}

	// 4. 文件读取完毕，关闭 jobs channel。Worker 收到信号后会把剩余任务做完再退出
	close(jobs)

	//5. 主协程阻塞等待所有 Worker 协程执行完毕
	wg.Wait()

	//  所有 Worker 结束后，刷新缓冲区确保数据全部落盘
	writer.Flush()

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "读取文件出错:", err)
	}
	fmt.Println("\n[+] 扫描完成，结果已保存到 results.csv")

}

// probe 负责实际的 HTTP 请求、失败重试以及响应信息的提取。
// 成长记录：
//	Day3 改成 goroutine 并发版（先跑通，不要求优雅）
//	Day4 改成 worker pool，用 -c 控制并发数
//	Day5 顺手把响应头 Server 和 <title> 一起取回来
//	Day6 结果同时输出成 results.csv
//	Day7 加上超时重试和 User-Agent 伪装

func probe(client *http.Client, url string, retries int) (int, string, string, error) {
	var resp *http.Response
	var err error

	// 自定义 User-Agent，伪装成 Chrome 浏览器，绕过基础 WAF 拦截
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	// 循环重试逻辑
	for i := 0; i < retries; i++ {
		// 1. 必须用 http.NewRequest 才能自定义请求头
		req, reqErr := http.NewRequest("GET", url, nil)
		if reqErr != nil {
			return 0, "", "", reqErr // URL 本身格式错误，重试也没用，直接返回
		}
		//2.穿上马甲
		req.Header.Set("User-Agent", userAgent)
		//3.发送请求
		resp, err = client.Do(req)

		// 如果请求成功且状态码小于 500（如 200、403），说明服务器已正常响应，直接跳出重试循环
		if err == nil && resp.StatusCode < 500 {
			break
		}

		// 准备重试前，必须关闭上一次请求的响应体，防止内存泄漏
		if resp != nil {
			resp.Body.Close() // 极其重要！重试前必须关闭上一次的 Body，否则内存泄漏
		}

		// 没到最后一次重试，歇 1 秒再试
		if i < retries-1 {
			time.Sleep(1 * time.Second)
		}
	}

	// 如果重试完了依然报错，返回最后的错误
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode
	server := resp.Header.Get("Server")
	if server == "" {
		server = "-" // 没拿到就显示横杠，保持输出整齐
	}

	// 读取 Body 内容，限制为前 1MB，防止读取巨型文件导致 OOM（内存溢出）
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return statusCode, server, "-", err
	}

	// 提取网页标题 <title>
	bodyStr := string(bodyBytes)
	title := "-"
	titleStart := strings.Index(bodyStr, "<title>")
	titleEnd := strings.Index(bodyStr, "</title>")

	if titleStart != -1 && titleEnd != -1 && titleEnd > titleStart {
		title = strings.TrimSpace(bodyStr[titleStart+7 : titleEnd])
		// 清洗标题中的换行符
		title = strings.ReplaceAll(title, "\n", " ")
		title = strings.ReplaceAll(title, "\r", " ")
		// 截断过长的标题，防止终端输出爆炸
		if len(title) > 30 {
			title = title[:30] + "..."
		}
	}
	return statusCode, server, title, nil
}
