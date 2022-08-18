package main

import "os"

func main() {
	v := detect()
	switch v {
	case 0:
		l := os.Args[2]
		r := os.Args[4]
		if os.Args[1] == "-p" {
			t := l
			l = r
			r = t
		}
		go func() {
			ProxyServer(r)
		}()
		InProxyServer(l)
	case 1:
		l := os.Args[2]
		r := os.Args[4]
		if os.Args[1] == "-p" {
			t := l
			l = r
			r = t
		}
		OutLocal(l, r)
	default:
		println(`usage: ioProxy [-i ip:port -p ip:port | -t ip:port -p ip:port]
ex:
  device <<-->> | device server <<-->> proxy server | <<-->> proxy terminal | <<-->> local port
      io        |            server                 |         client        |     target app 
`)
	}

}

func StringsContains(array []string, val string) (index int) {
	index = -1
	for i := 0; i < len(array); i++ {
		if array[i] == val {
			index = i
			return
		}
	}
	return
}

func detect() int {
	var t []string
	for _, v := range os.Args {
		t = append(t, v)
	}
	if len(t) > 4 && ((StringsContains(t, "-i") == 1 && StringsContains(t, "-p") == 3) ||
		(StringsContains(t, "-i") == 3 && StringsContains(t, "-p") == 1)) {
		return 0
	}
	if len(t) > 4 && ((StringsContains(t, "-t") == 1 && StringsContains(t, "-p") == 3) ||
		(StringsContains(t, "-t") == 3 && StringsContains(t, "-p") == 1)) {
		return 1
	}
	return -1
}
