package main

import (
	"fmt"
	"miao/tools"
)

func main() {
	banner := `
		|￣￣￣￣￣￣￣￣￣￣￣| 	
		 |                    |	
		 |  miaomiao~         |	        
		||＿＿＿＿＿＿＿＿＿＿_|        
	        ||                             
	 (\__/) ||          < portScan 端口扫描工具 >                    
	 (•ㅅ•) ||                           
	 / 　 づv               
	 `
	fmt.Println(banner)
	tools.PortScan()

}
