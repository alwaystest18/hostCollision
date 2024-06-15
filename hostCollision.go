package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Workiva/go-datastructures/queue"
	"github.com/antlabs/strsim"
	"github.com/go-resty/resty/v2"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/ratelimit"
	"github.com/remeh/sizedwaitgroup"
	"github.com/sirupsen/logrus"
)

var resultHostCollision []string

var wg sizedwaitgroup.SizedWaitGroup = sizedwaitgroup.New(100)

// 匹配程序接受的站点url格式
func CheckUrl(str string) bool {
	regCheckUrl := regexp.MustCompile(`http[s]?://\d+\.\d+\.\d+\.\d+(:\d+)?`)
	if regCheckUrl.MatchString(str) {
		return true
	} else {
		return false
	}
}

// 获取title内容
func GetTitle(body string) string {
	re := regexp.MustCompile(`<title>([\s\S]*?)</title>`)
	match := re.FindStringSubmatch(body)
	if match != nil && len(match) > 1 {
		return strings.TrimSpace(match[1])
	} else {
		return ""
	}
}

// 发起http请求，增加请求头Host
func GetPageContent(urlStr string, hostName string) (string, int, int, string, error) {
	//display 'Unsolicited response received on idle HTTP channel starting with "\n"; err=<nil>' error
	log.SetOutput(ioutil.Discard)

	//display "ERROR RESTY" error
	logger := logrus.New()
	logger.Out = ioutil.Discard

	client := resty.New().SetLogger(logger)
	//忽略证书错误
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	//设置超时时间
	client.SetTimeout(time.Duration(5 * time.Second))
	//设置请求头
	if hostName != "" {
		client.SetHeaders(map[string]string{
			"Host":            hostName,
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
			"Accept-Encoding": "gzip",
		})
	} else {
		client.SetHeaders(map[string]string{
			"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
			"Accept-Encoding": "gzip",
		})
	}
	//禁止跳转
	client.SetRedirectPolicy(resty.NoRedirectPolicy())
	//Connection: close
	client.SetCloseConnection(true)

	// Set retry
	client.SetRetryCount(1).SetRetryWaitTime(3 * time.Second).SetRetryMaxWaitTime(3 * time.Second)

	//发起http请求
	resp, err := client.R().Get(urlStr)
	if err != nil {
		return "", 0, 0, "", err
	}
	//读取http响应内容
	body := resp.String()
	title := GetTitle(body)
	lenPage := len(body)
	//截取返回内容，避免内容过大占用内存
	if lenPage > 2000 {
		body = body[:2000]
	}

	statusCode := resp.StatusCode()

	return body, statusCode, lenPage, title, nil
}

// 将文件内容转为字符列表
func FileContentToList(filePath string) []string {
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		gologger.Fatal().Msg("file open fail: " + filePath)
		return []string{""}
	}
	fileContentStr := strings.ReplaceAll(string(fileContent), "\r\n", "\n")
	contentList := strings.Split(fileContentStr, "\n")
	var newList []string
	for _, element := range contentList {
		if element != "" {
			newList = append(newList, element)
		}
	}
	return newList
}

// 生成随机字符串
func RandString(n int) string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// 替换domain
func ReplaceHostName(hostName string) string {
	hostParts := strings.Split(hostName, ".")
	hostParts[0] = RandString(10)
	testHostName := strings.Join(hostParts[0:], ".")

	return testHostName
}

// 判断字符串相似度（根据编辑距离）
func StrCompare(str1, str2 string) int {
	distance := strsim.Compare(str1, str2)
	intDistance := int(math.Floor(distance * 100))
	return intDistance
}

// 字符型列表去重去空
func UniqueStrList(strList []string) []string {
	uniqList := make([]string, 0)
	tempMap := make(map[string]bool, len(strList))
	for _, v := range strList {
		if tempMap[v] == false && len(v) > 0 {
			tempMap[v] = true
			uniqList = append(uniqList, v)
		}
	}
	return uniqList
}

// 对站点进行host碰撞
func HostCollision(urlStr string, hostsList []string) {
	defer wg.Done()
	//首先不带host请求ip，提取状态码与页面内容作为对比特征
	pageContent1, pageStatusCode1, pageLen1, _, err := GetPageContent(urlStr, "")
	if err != nil {
		return
	}
	for _, hostName := range hostsList {
		//对需要碰撞的host以.分隔，第一位替换为十位随机字符，如www.baidu.com替换后为xxxxxxxxxx.baidu.com,请求后提取状态码与页面内容作为对比特征
		testHostName := ReplaceHostName(hostName)
		pageContent2, pageStatusCode2, pageLen2, _, err := GetPageContent(urlStr, testHostName)
		if err != nil {
			continue
		}

		//对需要碰撞的host发起http请求，提取状态码与页面内容作为对比特征
		pageContent3, pageStatusCode3, pageLen3, pageTitle, err := GetPageContent(urlStr, hostName)
		if err != nil {
			continue
		}
		gologger.Info().Msgf("test url: %s    hostname: %s", urlStr, hostName)

		if len(pageContent3) < 200 {
			//两次测试请求成功且返回长度相同，如果枚举的host返回长度与测试请求不同则碰撞成功
			if pageLen1 == pageLen2 {
				if pageLen3 != pageLen1 {
					gologger.Silent().Msgf("[success] url: %s  host: %s  title:[%s]  Length: %d", urlStr, hostName, pageTitle, pageLen3)
					resultHostCollision = append(resultHostCollision,
						"url:"+urlStr+"  host:"+hostName+"  title:["+pageTitle+"]  Length: "+strconv.Itoa(pageLen3))
					continue
				}
				//两次测试请求成功且状态码相同，如果枚举的host状态码与测试请求不同则碰撞成功
			} else if pageStatusCode1 == pageStatusCode2 {
				if pageStatusCode3 != pageStatusCode2 {
					gologger.Silent().Msgf("[success] url: %s  host: %s  title:[%s]  Length: %d", urlStr, hostName, pageTitle, pageLen3)
					resultHostCollision = append(resultHostCollision,
						"url:"+urlStr+"  host:"+hostName+"  title:["+pageTitle+"]  Length: "+strconv.Itoa(pageLen3))
					continue
				}
			} else if pageLen1 != pageLen2 {
				if strings.Count(pageContent2, testHostName) > 0 {
					//如果两个错误的host返回结果长度不同，则很有可能是把host内容加到了页面内容中，此时我们需要减去hostname的长度后再做对比
					realLenPageContent2 := len(pageContent2) - len(testHostName)*strings.Count(pageContent2, testHostName)
					realLenPageContent3 := len(pageContent3) - len(hostName)*strings.Count(pageContent3, hostName)
					if realLenPageContent3 != realLenPageContent2 {
						gologger.Silent().Msgf("[success] url: %s  host: %s  title:[%s]  Length: %d", urlStr, hostName, pageTitle, pageLen3)
						resultHostCollision = append(resultHostCollision,
							"url:"+urlStr+"  host:"+hostName+"  title:["+pageTitle+"]  Length: "+strconv.Itoa(pageLen3))
						continue
					}
				} else {
					if pageLen3 != pageLen1 && pageLen3 != pageLen2 {
						gologger.Silent().Msgf("[success] url: %s  host: %s  title:[%s]  Length: %d", urlStr, hostName, pageTitle, pageLen3)
						resultHostCollision = append(resultHostCollision,
							"url:"+urlStr+"  host:"+hostName+"  title:["+pageTitle+"]  Length: "+strconv.Itoa(pageLen3))
						continue
					}
				}
			}
			//如果页面长度超过200则进行页面相似度对比，如果页面相差较大则判定碰撞成功
		} else if len(pageContent3) >= 200 {
			//页面内容中如出现hostname则替换为空，减少相似度对比的噪音
			pageContent1 = strings.Replace(pageContent1, hostName, "", -1)
			pageContent2 = strings.Replace(pageContent2, hostName, "", -1)
			pageContent3 = strings.Replace(pageContent3, hostName, "", -1)

			if StrCompare(pageContent3, pageContent1) < 85 && StrCompare(pageContent3, pageContent2) < 85 {
				gologger.Silent().Msgf("[success] url: %s  host: %s  title:[%s]  Length: %d", urlStr, hostName, pageTitle, pageLen3)
				resultHostCollision = append(resultHostCollision,
					"url:"+urlStr+"  host:"+hostName+"  title:["+pageTitle+"]  Length: "+strconv.Itoa(pageLen3))
				continue
			}
		}
	}
}

func main() {
	nowTime := time.Now().Format("200601021504")
	// 定义命令行参数
	uf := flag.String("uf", "", "url file path")
	df := flag.String("df", "", "domain file path")
	t := flag.Int64("t", 20, "Number of threads")
	r := flag.Int("r", 100, "rate limit")
	o := flag.String("o", "host_collision_success_"+nowTime+".txt", "output file name")
	silent := flag.Bool("silent", false, "silent mode")
	flag.Parse()

	urlFile := *uf
	domainFile := *df
	threads := *t
	rateLimit := uint(*r)
	outFileName := *o
	silentMode := *silent

	//安静模式，仅输出成功记录
	if silentMode {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}

	urlsList := FileContentToList(urlFile)
	hostsList := FileContentToList(domainFile)
	que := queue.New(threads)

	for _, urlStr := range urlsList {
		if CheckUrl(urlStr) {
			que.Put(urlStr)
		}
	}

	limiter := ratelimit.New(context.Background(), rateLimit, time.Duration(1*time.Second))

	for que.Len() > 0 {
		wg.Add()
		queList, _ := que.Get(1)
		urlStr := queList[0].(string)
		limiter.Take()
		go HostCollision(urlStr, hostsList)
	}
	wg.Wait()
	if len(resultHostCollision) > 0 {
		outFile, _ := os.OpenFile(outFileName, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0666)
		defer outFile.Close()
		sort.Strings(resultHostCollision)
		resultHostCollision = UniqueStrList(resultHostCollision)
		for _, resultInfo := range resultHostCollision {
			outFile.WriteString(resultInfo + "\n")

		}
	}
}
