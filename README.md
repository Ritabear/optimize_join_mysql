# Group 5 PoC

This code shows our proposed approach.

## Environment

- Go 1.20.4

### Package

- github.com/emirpasic/gods v1.18.1
- github.com/go-sql-driver/mysql v1.7.1

### Package Installation

```bash
go get .
```

## Database Config
Please edit the file in config/config.go

## Run

```bash
go run main.go
```

### Expected Output
```
2023/06/19 07:16:02 demo1_ptr.go:32: Demo 1 start.
2023/06/19 07:16:02 demo1_ptr.go:35: Connect to DB.
2023/06/19 07:16:02 demo1_ptr.go:48: Select the first table.
2023/06/19 07:16:02 demo1.go:58:        Alloc = 0 MiB
2023/06/19 07:16:02 demo1.go:59:        totalAlloc = 0 MiB
2023/06/19 07:16:02 demo1.go:60:        Sys = 11 MiB
2023/06/19 07:16:02 demo1.go:61:        NumGC = 0
2023/06/19 07:16:02 demo1_ptr.go:80: Select and join the second table.
2023/06/19 07:16:25 demo1_ptr.go:127: Found 776998 rows.
2023/06/19 07:16:25 demo1.go:58:        Alloc = 204 MiB
2023/06/19 07:16:25 demo1.go:59:        totalAlloc = 4776 MiB
2023/06/19 07:16:25 demo1.go:60:        Sys = 264 MiB
2023/06/19 07:16:25 demo1.go:61:        NumGC = 123
2023/06/19 07:16:25 demo1_ptr.go:145: Select and join the third table.
2023/06/19 07:18:48 demo1_ptr.go:200: Found 781306132 rows.
2023/06/19 07:18:48 demo1.go:58:        Alloc = 14235 MiB
2023/06/19 07:18:48 demo1.go:59:        totalAlloc = 77541 MiB
2023/06/19 07:18:48 demo1.go:60:        Sys = 34257 MiB
2023/06/19 07:18:48 demo1.go:61:        NumGC = 145
2023/06/19 07:18:48 demo1_ptr.go:205: Group tables by id, group, and malicious.
2023/06/19 07:19:46 demo1_ptr.go:254: Group into 913 rows.
2023/06/19 07:19:46 demo1.go:58:        Alloc = 24418 MiB
2023/06/19 07:19:46 demo1.go:59:        totalAlloc = 128897 MiB
2023/06/19 07:19:46 demo1.go:60:        Sys = 36805 MiB
2023/06/19 07:19:46 demo1.go:61:        NumGC = 148
2023/06/19 07:19:46 demo1_ptr.go:259: Calculate function counts.
2023/06/19 07:20:15 demo1.go:58:        Alloc = 24508 MiB
2023/06/19 07:20:15 demo1.go:59:        totalAlloc = 128987 MiB
2023/06/19 07:20:15 demo1.go:60:        Sys = 36805 MiB
2023/06/19 07:20:15 demo1.go:61:        NumGC = 148
2023/06/19 07:20:15 demo1_ptr.go:284: Sort by malicious and ida_func_count.
2023/06/19 07:20:15 demo1_ptr.go:293: Task finished.
2023/06/19 07:20:15 demo1.go:58:        Alloc = 24508 MiB
2023/06/19 07:20:15 demo1.go:59:        totalAlloc = 128987 MiB
2023/06/19 07:20:15 demo1.go:60:        Sys = 36805 MiB
2023/06/19 07:20:15 demo1.go:61:        NumGC = 148
```
