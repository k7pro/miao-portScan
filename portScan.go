package tools

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"github.com/Ullaakut/nmap/v3"
	"github.com/fatih/color"
	"github.com/go-ping/ping"
	"github.com/xuri/excelize/v2"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

/*
工具实现思路细分
1、对获取的 -p 参数的格式进行校验，判断合法性
2、对合法的-p参数值进行拆解成具体的端口号，进行后续值传递
3、对每个端口进行存活探测
4、调用第三方库进行端口服务识别

*/

type Address struct {
	IP   string
	Port []Banner
}

type Banner struct {
	Port   string
	Finger string
}

// 端口号格式判断函数，对输入的-p参数进行值的格式校验，合法返回true，反之返回false
func checkFormat(port string) bool {

	// 检查是否为int格式且范围在1-65535之间
	intPort, err := strconv.Atoi(port)
	if err == nil && intPort > 0 && intPort < 65536 {
		return true
	}

	// 检查多个端口号是否以逗号进行分割,且分割的每个元素是否为int格式且范围在1-65535之间
	// 至少两个部分，才证明使用的多个端口号的模式
	splitPort := strings.Split(port, ",")
	if len(splitPort) > 1 {
		isLegal := true
		for _, port := range splitPort {
			intPort, err := strconv.Atoi(port)
			if err != nil || intPort < 0 || intPort > 65536 {
				isLegal = false
			}
		}
		return isLegal
	}

	// 检查端口号范围
	splitPort = strings.Split(port, "-")
	if len(splitPort) == 2 {
		startPort, err1 := strconv.Atoi(splitPort[0])
		endPort, err2 := strconv.Atoi(splitPort[1])
		if err1 != nil || err2 != nil || startPort < 0 || startPort > 65536 || endPort < 0 || endPort > 65536 {
			return false
		}
		return true
	}

	// 检查是否为top100或top1000
	if port == "top100" || port == "top1000" {
		return true
	}

	return false
}

// 具体端口号拆分
func splitPort(port string) []string {
	var portSlice []string

	// 检查是否为一个端口
	_, err := strconv.Atoi(port)
	if err == nil {
		portSlice = append(portSlice, port)
	}

	// 先检查输入的是什么类型
	// 拆分多个端口
	if strings.Contains(port, ",") {
		portSlice = strings.Split(port, ",")
	}

	// 拆分端口范围
	if strings.Contains(port, "-") {
		intPort1, _ := strconv.Atoi(strings.Split(port, "-")[0])
		intPort2, _ := strconv.Atoi(strings.Split(port, "-")[1])

		for i := intPort1; i <= intPort2; i++ {
			portSlice = append(portSlice, strconv.Itoa(i))
		}
	}

	// 常用端口合集
	if port == "top100" {
		portSlice = []string{
			"21", "22", "80", "81", "135", "139", "443", "445", "1433", "1521", "3306", "5432", "6379", "7001", "8000", "8080", "8089",
			"9000", "9200", "11211", "27017", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91",
			"1000", "1010", "1080", "1081", "1082", "1099", "2008",
			"2375", "2379", "7000", "7002", "7003",
			"7004", "7005", "7007", "7008", "7070", "7071", "7074", "7078", "7080", "7088", "7200", "7680", "7687", "7688", "7777",
			"7890", "8001", "8002", "8003", "8004", "8006", "8008", "8009", "8010", "8011", "8012", "8016", "8018", "8020",
			"8028", "8030", "8038", "8042", "8044", "8046", "8048", "8053", "8060", "8069", "8070", "8081", "8082", "8083",
			"8084", "8085", "8086", "8087", "8088", "8089", "8090", "8091", "8092", "8093", "8094", "8095", "8096", "8097", "8098",
			"8099", "8100", "8101", "8108", "8118", "8161", "8172", "8180", "8181", "8200", "8222", "8244", "8258", "8280", "8288",
			"8300", "8360", "8443", "8448", "8484", "8800", "8834", "8848", "8858", "8888",
			"9001", "9002", "9008", "9010", "9043", "9060", "9080", "9090",
			"9443", "9448", "10000", "10001", "10002", "10004",
			"10008", "10010", "10250", "12018", "12443", "14000", "16080", "18000", "18001", "18002", "18004", "18008", "18080",
			"18082", "18088", "18090", "18098", "19001", "20000", "20720", "21000", "21501", "21502", "28018", "20880",
		}
	}

	if port == "top1000" {
		portSlice = []string{
			"20", "21", "22", "23", "24", "25", "26", "30", "32", "33", "37", "42", "43", "49", "53", "70", "79", "80", "81", "82",
			"83", "84", "85", "88", "89", "90", "99", "100", "106", "109", "110", "111", "113", "119", "125", "135", "139", "143",
			"144", "146", "161", "163", "179", "199", "211", "212", "222", "254", "255", "256", "259", "264", "280", "301", "306",
			"311", "340", "366", "389", "406", "407", "416", "417", "425", "427", "443", "444", "445", "458", "464", "465", "481",
			"497", "500", "512", "513", "514", "515", "524", "541", "543", "544", "545", "548", "554", "555", "563", "587", "593",
			"616", "617", "625", "631", "636", "646", "648", "666", "667", "668", "683", "687", "691", "700", "705", "711", "714",
			"720", "722", "726", "749", "765", "777", "783", "787", "800", "801", "808", "843", "873", "880", "888", "898", "900",
			"901", "902", "903", "911", "912", "981", "987", "990", "992", "993", "995", "999", "1000", "1001", "1002", "1007",
			"1009", "1010", "1011", "1021", "1022", "1023", "1024", "1025", "1026", "1027", "1028", "1029", "1030", "1031", "1032",
			"1033", "1034", "1035", "1036", "1037", "1038", "1039", "1040", "1041", "1042", "1043", "1044", "1045", "1046", "1047",
			"1048", "1049", "1050", "1051", "1052", "1053", "1054", "1055", "1056", "1057", "1058", "1059", "1060", "1061", "1062",
			"1063", "1064", "1065", "1066", "1067", "1068", "1069", "1070", "1071", "1072", "1073", "1074", "1075", "1076", "1077",
			"1078", "1079", "1080", "1081", "1082", "1083", "1084", "1085", "1086", "1087", "1088", "1089", "1090", "1091", "1092",
			"1093", "1094", "1095", "1096", "1097", "1098", "1099", "1100", "1102", "1104", "1105", "1106", "1107", "1108", "1110",
			"1111", "1112", "1113", "1114", "1117", "1119", "1121", "1122", "1123", "1124", "1126", "1130", "1131", "1132", "1137",
			"1138", "1141", "1145", "1147", "1148", "1149", "1151", "1152", "1154", "1163", "1164", "1165", "1166", "1169", "1174",
			"1175", "1183", "1185", "1186", "1187", "1192", "1198", "1199", "1201", "1213", "1216", "1217", "1218", "1233", "1234",
			"1236", "1244", "1247", "1248", "1259", "1271", "1272", "1277", "1287", "1296", "1300", "1301", "1309", "1310", "1311",
			"1322", "1328", "1334", "1352", "1417", "1433", "1434", "1443", "1455", "1461", "1494", "1500", "1501", "1503", "1521",
			"1524", "1533", "1556", "1580", "1583", "1594", "1600", "1641", "1658", "1666", "1687", "1688", "1700", "1717", "1718",
			"1719", "1720", "1721", "1723", "1755", "1761", "1782", "1783", "1801", "1805", "1812", "1839", "1840", "1862", "1863",
			"1864", "1875", "1900", "1914", "1935", "1947", "1971", "1972", "1974", "1984", "1998", "1999", "2000", "2001", "2002",
			"2003", "2004", "2005", "2006", "2007", "2008", "2009", "2010", "2013", "2020", "2021", "2022", "2030", "2033", "2034",
			"2035", "2038", "2040", "2041", "2042", "2043", "2045", "2046", "2047", "2048", "2049", "2065", "2068", "2099", "2100",
			"2103", "2105", "2106", "2107", "2111", "2119", "2121", "2126", "2135", "2144", "2160", "2161", "2170", "2179", "2190",
			"2191", "2196", "2200", "2222", "2251", "2260", "2288", "2301", "2323", "2366", "2381", "2382", "2383", "2393", "2394",
			"2399", "2401", "2492", "2500", "2522", "2525", "2557", "2601", "2602", "2604", "2605", "2607", "2608", "2638", "2701",
			"2702", "2710", "2717", "2718", "2725", "2800", "2809", "2811", "2869", "2875", "2909", "2910", "2920", "2967", "2968",
			"2998", "3000", "3001", "3003", "3005", "3006", "3007", "3011", "3013", "3017", "3030", "3031", "3052", "3071", "3077",
			"3128", "3168", "3211", "3221", "3260", "3261", "3268", "3269", "3283", "3300", "3301", "3306", "3322", "3323", "3324",
			"3325", "3333", "3351", "3367", "3369", "3370", "3371", "3372", "3389", "3390", "3404", "3476", "3493", "3517", "3527",
			"3546", "3551", "3580", "3659", "3689", "3690", "3703", "3737", "3766", "3784", "3800", "3801", "3809", "3814", "3826",
			"3827", "3828", "3851", "3869", "3871", "3878", "3880", "3889", "3905", "3914", "3918", "3920", "3945", "3971", "3986",
			"3995", "3998", "4000", "4001", "4002", "4003", "4004", "4005", "4006", "4045", "4111", "4125", "4126", "4129", "4224",
			"4242", "4279", "4321", "4343", "4443", "4444", "4445", "4446", "4449", "4550", "4567", "4662", "4848", "4899", "4900",
			"4998", "5000", "5001", "5002", "5003", "5004", "5009", "5030", "5033", "5050", "5051", "5054", "5060", "5061", "5080",
			"5087", "5100", "5101", "5102", "5120", "5190", "5200", "5214", "5221", "5222", "5225", "5226", "5269", "5280", "5298",
			"5357", "5405", "5414", "5431", "5432", "5440", "5500", "5510", "5544", "5550", "5555", "5560", "5566", "5631", "5633",
			"5666", "5678", "5679", "5718", "5730", "5800", "5801", "5802", "5810", "5811", "5815", "5822", "5825", "5850", "5859",
			"5862", "5877", "5900", "5901", "5902", "5903", "5904", "5906", "5907", "5910", "5911", "5915", "5922", "5925", "5950",
			"5952", "5959", "5960", "5961", "5962", "5963", "5987", "5988", "5989", "5998", "5999", "6000", "6001", "6002", "6003",
			"6004", "6005", "6006", "6007", "6009", "6025", "6059", "6100", "6101", "6106", "6112", "6123", "6129", "6156", "6346",
			"6379", "6389", "6502", "6510", "6543", "6547", "6565", "6566", "6567", "6580", "6646", "6666", "6667", "6668", "6669",
			"6689", "6692", "6699", "6779", "6788", "6789", "6792", "6839", "6881", "6901", "6969", "7000", "7001", "7002", "7004",
			"7007", "7019", "7025", "7070", "7100", "7103", "7106", "7200", "7201", "7402", "7435", "7443", "7496", "7512", "7625",
			"7627", "7676", "7741", "7777", "7778", "7800", "7911", "7920", "7921", "7937", "7938", "7999", "8000", "8001", "8002",
			"8007", "8008", "8009", "8010", "8011", "8021", "8022", "8031", "8042", "8045", "8080", "8081", "8082", "8083", "8084",
			"8085", "8086", "8087", "8088", "8089", "8090", "8093", "8099", "8100", "8180", "8181", "8192", "8193", "8194", "8200",
			"8222", "8254", "8290", "8291", "8292", "8300", "8333", "8383", "8400", "8402", "8443", "8500", "8600", "8649", "8651",
			"8652", "8654", "8701", "8800", "8873", "8888", "8899", "8994", "9000", "9001", "9002", "9003", "9009", "9010", "9011",
			"9040", "9050", "9071", "9080", "9081", "9090", "9091", "9099", "9100", "9101", "9102", "9103", "9110", "9111", "9200",
			"9207", "9220", "9290", "9415", "9418", "9485", "9500", "9502", "9503", "9535", "9575", "9593", "9594", "9595", "9618",
			"9666", "9876", "9877", "9878", "9898", "9900", "9917", "9929", "9943", "9944", "9968", "9998", "9999", "10000", "10001",
			"10002", "10003", "10004", "10009", "10010", "10012", "10024", "10025", "10082", "10180", "10215", "10243", "10566",
			"10616", "10617", "10621", "10626", "10628", "10629", "10778", "11110", "11111", "11967", "12000", "12174", "12265",
			"12345", "13456", "13722", "13782", "13783", "14000", "14238", "14441", "14442", "15000", "15002", "15003", "15004",
			"15660", "15742", "16000", "16001", "16012", "16016", "16018", "16080", "16113", "16992", "16993", "17877", "17988",
			"18040", "18101", "18988", "19101", "19283", "19315", "19350", "19780", "19801", "19842", "20000", "20005", "20031",
			"20221", "20222", "20828", "21571", "22939", "23502", "24444", "24800", "25734", "25735", "26214", "27000", "27352",
			"27353", "27355", "27356", "27715", "28201", "30000", "30718", "30951", "31038", "31337", "32768", "32769", "32770",
			"32771", "32772", "32773", "32774", "32775", "32776", "32777", "32778", "32779", "32780", "32781", "32782", "32783",
			"32784", "32785", "33354", "33899", "34571", "34572", "34573", "35500", "38292", "40193", "40911", "41511", "42510",
			"44176", "44442", "44443", "44501", "45100", "48080", "49152", "49153", "49154", "49155", "49156", "49157", "49158",
			"49159", "49160", "49161", "49163", "49165", "49167", "49175", "49176", "49400", "49999", "50000", "50001", "50002",
			"50003", "50006", "50300", "50389", "50500", "50636", "50800", "51103", "51493", "52673", "52822", "52848", "52869",
			"54045", "54328", "55055", "55056", "55555", "55600", "56737", "56738", "57294", "57797", "58080", "60020", "60443",
			"61532", "61900", "62078", "63331", "64623", "64680", "65000", "65129", "65389",
		}
	}

	return portSlice
}

// ip格式校验
func ipFormatCheck(ip string) []string {
	var ipSlice []string

	// 判断是否为单个ip格式
	if net.ParseIP(ip) != nil {
		ipSlice = append(ipSlice, ip)
	}

	// 判断是否为多个ip,以逗号分割的多个ip
	if strings.Contains(ip, ",") {
		ips := strings.Split(ip, ",")
		for _, ip2 := range ips {
			if net.ParseIP(ip2) != nil {
				ipSlice = append(ipSlice, ip2)
			}
		}
	}

	// 192.168.137.1/24
	/*
		1、10.1.1.2
		2、10.1.1.2
	*/

	// 定义局部递增函数,用于后续ip段的判断
	inc := func(ip net.IP) {
		for j := len(ip) - 1; j >= 0; j-- {
			ip[j]++
			if ip[j] > 0 {
				break
			}
		}
	}

	// 判断是否为ip段
	_, ipNet, err := net.ParseCIDR(ip)
	if err == nil {
		for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
			ipSlice = append(ipSlice, ip.String())
		}

		// 去掉网络地址和广播地址（假设子网大小 > 2）
		if len(ipSlice) > 2 {
			ipSlice = ipSlice[1 : len(ipSlice)-1]
		}
	}

	// 判断ip范围
	if strings.Contains(ip, "-") {
		ips := strings.Split(ip, "-")
		start, _ := strconv.Atoi(strings.Split(ips[0], ".")[3])
		end, _ := strconv.Atoi(ips[1])

		for i := start; i <= end; i++ {
			// 获取ip切片中的第一个ip
			ipIndex1 := ips[0]

			// 提取第一个ip的前三位
			ipIndex1Index3 := strings.Split(ipIndex1, ".")[0:3]
			ipstr := strings.Join(ipIndex1Index3, ".")

			// 拼接成完整ip
			ipSlice = append(ipSlice, ipstr+"."+strconv.Itoa(i))
		}
	}

	fmt.Printf("共发现%d个ip\n", len(ipSlice))
	return ipSlice
}

// 端口开放扫描
func openPort(ipSlice []string, portSlice []string, thread int) map[string][]string {

	color.Green("扫描开放端口 --------------------")
	fileWrite("扫描开放端口 --------------------")

	// 定义一个map，key为ip，value为开放的端口切片
	portMap := make(map[string][]string)

	var mutex sync.Mutex // 添加互斥锁保护map

	// 转换

	var wg sync.WaitGroup
	sem := make(chan struct{}, thread)
	for _, port := range portSlice {
		for _, ip := range ipSlice {
			wg.Add(1)
			sem <- struct{}{}

			go func(ip string, port string) {
				defer wg.Done()
				defer func() { <-sem }()

				host := fmt.Sprintf("%s:%s", ip, port)
				conn, err := net.DialTimeout("tcp", host, 2*time.Second)

				if err == nil {
					defer conn.Close()

					mutex.Lock()
					portMap[ip] = append(portMap[ip], port)
					mutex.Unlock()

					fmt.Println(host) // 原子性输出日志
					fileWrite(host)
				}

			}(ip, port) // 传递当前值
		}
	}
	wg.Wait()

	fmt.Println("")
	return portMap

}

type ScanResult struct {
	IP      string
	Port    int
	Service string
	Status  string
	Version string
}

// 调用nmap的库进行服务识别
func bannerScanner(portMap map[string][]string) []ScanResult {

	color.Green("端口服务探测 --------------------")
	//fmt.Println("端口服务探测 --------------------")
	fileWrite("端口服务探测 --------------------")

	var scanResult ScanResult
	var scanResultSlice []ScanResult

	var nmapBinary string
	if runtime.GOOS == "windows" {
		nmapBinary = "lib/nmap/nmap.exe"
	}
	if runtime.GOOS == "linux" {
		nmapBinary = ""
	}

	for ip, portSlice := range portMap {

		// 1. 首先创建context
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		// 2. 创建扫描器（第一个参数必须是context）
		scanner, err := nmap.NewScanner(
			ctx, // 第一个参数是context
			nmap.WithTargets(ip),
			nmap.WithPorts(strings.Join(portSlice, ",")),
			nmap.WithSkipHostDiscovery(), // -Pn
			nmap.WithBinaryPath(nmapBinary),
		)
		if err != nil {
			log.Fatal(err)
		}

		// 3. 执行扫描
		result, warnings, err := scanner.Run()
		if err != nil {
			log.Fatal(err)
		}

		if len(*warnings) > 0 {
			fmt.Println("警告:", warnings)
		}

		// 4. 解析结果
		for _, host := range result.Hosts {
			color.Yellow("[ip] %s\n", host.Addresses[0].Addr)

			for _, port := range host.Ports {
				fmt.Printf("%d/%s: %s %s %s\n",
					port.ID,
					port.Protocol,
					port.State.State,
					port.Service.Name,
					port.Service.Version)

				fileWrite(fmt.Sprintf("%d/%s: %s %s %s",
					port.ID,
					port.Protocol,
					port.State.State,
					port.Service.Name,
					port.Service.Version))

				// 将参数值依次赋值给scanResult结构体
				scanResult.IP = host.Addresses[0].Addr
				scanResult.Port = int(port.ID)
				scanResult.Status = port.State.State
				scanResult.Service = port.Service.Name
				scanResult.Version = port.Service.Version

				scanResultSlice = append(scanResultSlice, scanResult)
			}
		}
	}

	fmt.Println("")
	return scanResultSlice

}

func saveToExcel(results []ScanResult, filename string) error {
	// 1. 检查并创建result目录（如果不存在）
	if _, err := os.Stat("result"); os.IsNotExist(err) {
		if err := os.Mkdir("result", 0755); err != nil {
			return fmt.Errorf("创建result目录失败: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("检查result目录失败: %v", err)
	}

	f := excelize.NewFile()
	defer f.Close()

	// 创建工作表
	index, _ := f.NewSheet("端口信息")
	f.SetActiveSheet(index)

	// 设置表头
	headers := []string{"IP", "端口", "状态", "服务"}
	for col, header := range headers {
		cell, _ := excelize.CoordinatesToCellName(col+1, 1)
		f.SetCellValue("端口信息", cell, header)
	}

	// 填充数据
	for row, result := range results {
		data := []interface{}{
			result.IP,
			result.Port,
			result.Status,
			result.Service,
		}
		for col, value := range data {
			cell, _ := excelize.CoordinatesToCellName(col+1, row+2)
			f.SetCellValue("端口信息", cell, value)
		}
	}

	// 设置列宽
	f.SetColWidth("端口信息", "A", "A", 18)
	f.SetColWidth("端口信息", "B", "C", 10)
	f.SetColWidth("端口信息", "D", "D", 15)

	// 添加表格的表头样式
	style, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "#FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#4F81BD"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})
	f.SetCellStyle("端口信息", "A1", "D1", style)

	// 添加表格的数据样式
	style2, _ := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})
	f.SetCellStyle("端口信息", "A2", "E100", style2)

	// 保存文件
	if err := f.SaveAs(filename); err != nil {
		return err
	}

	return nil
}

func fileWrite(content string) {
	// 以追加模式打开文件，权限设置为0666（所有人可读写）
	file, err := os.OpenFile("result.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return
	}
	defer file.Close()

	file.WriteString(content + "\n")
}

func ipAliveCheck(thread int, ipSlice []string) []string {
	fmt.Println("ip存活探测 --------------------")

	var ipAliveSlice []string

	//var mu sync.Mutex // 保护ipAliveSlice的并发访问
	var wg sync.WaitGroup
	sem := make(chan struct{}, 200)

	// 存放ping不通的ip
	var dieIPSlice []string

	for _, ip := range ipSlice {
		wg.Add(1)
		sem <- struct{}{}
		ip := ip
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			pinger, err := ping.NewPinger(ip)
			if err != nil {
				return
			}

			pinger.Count = 3
			pinger.Timeout = time.Second * 5
			pinger.SetPrivileged(true) // 在Linux上需要root权限

			pinger.OnFinish = func(stats *ping.Statistics) {
				// 至少收到一个回复，认为可以ping通
				if stats.PacketsRecv > 0 {
					fmt.Println(ip)
					ipAliveSlice = append(ipAliveSlice, ip)
				} else {
					dieIPSlice = append(dieIPSlice, ip)
				}
			}

			err = pinger.Run()
			if err != nil {
				return
			}

		}()

	}
	wg.Wait()

	// 第二种检测存活的思路，扫描常用的20个端口，如果发现有一个开放，则证明此ip存活
	portSlice := []string{
		"21", "22", "80", "81", "135", "139", "443", "445", "1433", "1521", "3306", "5432", "6379", "7001", "8000", "8080", "8089",
		"9000", "9200", "11211", "27017", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91",
		"1000", "1010", "1080", "1081", "1082", "1099", "2008",
		"2375", "2379", "7000", "7002", "7003",
		"7004", "7005", "7007", "7008", "7070", "7071", "7074", "7078", "7080", "7088", "7200", "7680", "7687", "7688", "7777",
		"7890", "8001", "8002", "8003", "8004", "8006", "8008", "8009", "8010", "8011", "8012", "8016", "8018", "8020",
		"8028", "8030", "8038", "8042", "8044", "8046", "8048", "8053", "8060", "8069", "8070", "8081", "8082", "8083",
		"8084", "8085", "8086", "8087", "8088", "8089", "8090", "8091", "8092", "8093", "8094", "8095", "8096", "8097", "8098",
		"8099", "8100", "8101", "8108", "8118", "8161", "8172", "8180", "8181", "8200", "8222", "8244", "8258", "8280", "8288",
		"8300", "8360", "8443", "8448", "8484", "8800", "8834", "8848", "8858", "8888",
		"9001", "9002", "9008", "9010", "9043", "9060", "9080", "9090",
		"9443", "9448", "10000", "10001", "10002", "10004",
		"10008", "10010", "10250", "12018", "12443", "14000", "16080", "18000", "18001", "18002", "18004", "18008", "18080",
		"18082", "18088", "18090", "18098", "19001", "20000", "20720", "21000", "21501", "21502", "28018", "20880",
	}

	fmt.Println("运行端口扫描探测ip存活")
	var isBreak bool
	for _, ip := range dieIPSlice {
		for _, port := range portSlice {
			wg.Add(1)
			sem <- struct{}{}

			go func(ip string, port string) {
				defer wg.Done()
				defer func() { <-sem }()

				host := fmt.Sprintf("%s:%s", ip, port)
				conn, err := net.DialTimeout("tcp", host, 2*time.Second)

				if err == nil {
					defer conn.Close()

					fmt.Println(ip) // 原子性输出日志
					fileWrite(host)
					ipAliveSlice = append(ipAliveSlice, ip)
					fmt.Println("发现存活：", host)

					isBreak = true
					return
				} else {
					isBreak = false
				}

			}(ip, port) // 传递当前值

			if isBreak {
				break
			}
		}

	}
	wg.Wait()

	fmt.Println("存活的ip数量：", len(ipAliveSlice))
	return ipAliveSlice

}

func PortScan() {
	portInput := flag.String("p", "top1000", "指定要扫描的端口，合法格式举例:<80> <22,80,3306> <100-1000> <top100> <top1000>")
	ipInput := flag.String("ip", "", "输入要扫描的目标ip，支持格式：<10.1.1.2> <10.1.1.1,10.1.1.2,10.1.1.3> <10.1.1.1-6> <10.1.1.0/24>")
	fileInput := flag.String("l", "", "指定ip文件进行批量扫描，每行一个ip")
	threadInput := flag.Int("thread", 200, "指定扫描线程")
	flag.Parse()

	port := *portInput
	ip := *ipInput
	file := *fileInput
	thread := *threadInput

	// 计算花费时间
	startTime := time.Now()

	// 检测是否输入目标
	if ip == "" && file == "" {
		fmt.Println("未指定目标 可通过-h查看用法")
		return
	}

	// 定义一个字符串切片用于存放ip
	var ipSlice []string

	// 检测port参数格式
	if !checkFormat(port) {
		fmt.Println("端口输入格式不合法:", port)
		return
	}

	// 获取具体端口内容
	portSlice := splitPort(port)

	// 判断是通过ip参数传参还是通过文件传参
	if ip != "" {
		fmt.Println("输入目标：", color.YellowString(ip))
		fileWrite(fmt.Sprintf("探测目标：%s", ip))

		// 检测ip参数格式是否合法，获取具体的ip
		ipSlice = ipFormatCheck(ip)
		if len(ipSlice) == 0 {
			fmt.Println("ip格式输入有误 可通过-h查看用法")
			return
		}
	} else if file != "" {
		fmt.Println("输入目标：", color.YellowString(file))
		fileWrite(fmt.Sprintf("探测目标：%s", file))

		openFile, err := os.Open(file)
		if err != nil {
			fmt.Println("文件读取失败:", err)
			return
		}
		defer openFile.Close()

		scanner := bufio.NewScanner(openFile)
		for scanner.Scan() {
			ipSlice = append(ipSlice, scanner.Text())
		}
	}

	// 剔除不存活的ip，获取存活ip
	//aliveIpSlice := ipAliveCheck(thread, ipSlice)

	// 扫描开放端口
	portMap := openPort(ipSlice, portSlice, thread)

	// 识别服务
	scanResult := bannerScanner(portMap)

	timestamp := time.Now().Format("20060102_1504")

	// 将结果保存到excel表中
	saveToExcel(scanResult, "result/portResult-"+timestamp+".xlsx")

	// 花费时间计算
	fmt.Println("运行完毕，花费时间:", time.Since(startTime))

}
