package main

import(
  "os"
  "dbproj_poc/demo1"
)

func main(){
  if os.Args[1] == "1" {
    demo1.RunPtr()
  }
}
