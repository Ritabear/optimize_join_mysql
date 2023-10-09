package demo1

import(
  "log"
  "fmt"
  "database/sql"
  "sort"
  "runtime"

  _ "github.com/go-sql-driver/mysql"
  "github.com/emirpasic/gods/utils"
  rbt "github.com/emirpasic/gods/trees/redblacktree"

  "dbproj_poc/config"
)

type sample struct {
  id      int
  group   int
  mal     bool
}

type funcInfo struct {
  id      int
  sid     int
  addr    int
}

type combinedRow struct {
  left    interface{}
  right   interface{}
}

type groupKey struct {
  id                    int
  group                 int
  mal                   bool
}

type groupRow struct {
  groupKey
  data                  []*combinedRow
  r2_func_count         int
  ida_func_count        int
  common_records_count  int
}

const GROUP int = 15

func bToMb(b uint64) uint64 {
    return b / 1024 / 1024
}

func PrintMemUsage() {
  var m runtime.MemStats
  runtime.ReadMemStats(&m)
  // For info on each, see: https://golang.org/pkg/runtime/#MemStats
  log.Printf("\tAlloc = %v MiB\n", bToMb(m.Alloc))
  log.Printf("\ttotalAlloc = %v MiB\n", bToMb(m.TotalAlloc))
  log.Printf("\tSys = %v MiB\n", bToMb(m.Sys))
  log.Printf("\tNumGC = %v\n", m.NumGC)
}

func Run(){
  log.SetFlags(log.LstdFlags | log.Lshortfile)
  log.Println("Demo 1 start.")

  // connect to db
  log.Println("Connect to DB.")
  conn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
                config.USERNAME,
                config.PASSWORD,
                config.ADDR,
                config.PORT,
                config.DEMO1_DB)
  db, err := sql.Open("mysql", conn)
  if err != nil {
    log.Fatal(err)
  }

  // select the first table
  log.Println("Select the first table.")
  stmt, err := db.Prepare("SELECT ID, `Group`, Malicious FROM Samples WHERE Valid=True AND `Group`=?")
  if err != nil {
    log.Fatal(err)
  }
  rows, err := stmt.Query(GROUP)

  samples := make([]sample, 0, 0)
  for rows.Next() {
    var tmpSample sample
    err = rows.Scan(&tmpSample.id, &tmpSample.group, &tmpSample.mal)
    if err != nil {
      log.Fatal(err)
    }
    samples = append(samples, tmpSample)
  }

  // build rbtree for samples
  samplesRBT := rbt.NewWith(func(a, b interface{}) int {
    return utils.IntComparator(a, b)
  })
  for idx:=0; idx<len(samples); idx++ {
    if subSamples, exists := samplesRBT.Get(samples[idx].id); !exists {
      samplesRBT.Put(samples[idx].id, [](*sample){&samples[idx]})
    } else {
      samplesRBT.Put(samples[idx].id, append(subSamples.([](*sample)), &samples[idx]))
    }
  }

  PrintMemUsage()

  // select the second table
  log.Println("Select and join the second table.")
  rows, err = db.Query("SELECT ID, SID, Addr FROM r2_func")
  if err != nil {
    log.Fatal(err)
  }

  combinedRows := make([]combinedRow, 0, 0)
  funcInfos := make([]funcInfo, 0, 0)
  rowsCount := 0
  for rows.Next() {
    rowsCount += 1
    // read func
    var tmpFuncInfo funcInfo
    err = rows.Scan(&tmpFuncInfo.id, &tmpFuncInfo.sid, &tmpFuncInfo.addr)
    if err != nil {
      log.Fatal(err)
    }

    // inner join
    /*
    saved := false
    for idx:=0; idx<len(samples); idx++ {
      if samples[idx].id == tmpFuncInfo.sid {
        if !saved {
          funcInfos = append(funcInfos, tmpFuncInfo)
          saved = true
        }
        combinedRows = append(combinedRows, combinedRow{left: &samples[idx], right: &funcInfos[len(funcInfos)-1]})
      }
    }
    */
    if subSamples, exists := samplesRBT.Get(tmpFuncInfo.sid); exists {
      saved := false
      for _, sampleAddr := range(subSamples.([](*sample))) {
        if !saved {
          funcInfos = append(funcInfos, tmpFuncInfo)
          saved = true
        }
        combinedRows = append(combinedRows, combinedRow{left: sampleAddr, right: &funcInfos[len(funcInfos)-1]})
      }
    }
  }

  // delete samplesRBT
  samplesRBT.Clear()


  // build rbtree for joined table
  tableRBT := rbt.NewWith(func(a, b interface{}) int {
    return utils.IntComparator(a, b)
  })
  for idx:=0; idx<len(combinedRows); idx++ {
    id := combinedRows[idx].left.(*sample).id
    if subRows, exists := tableRBT.Get(id); !exists {
      tableRBT.Put(id, [](*combinedRow){&combinedRows[idx]})
    } else {
      tableRBT.Put(id, append(subRows.([](*combinedRow)), &combinedRows[idx]))
    }
  }

  PrintMemUsage()

  // select the third table
  log.Println("Select and join the third table.")
  rows, err = db.Query("SELECT ID, SID, Addr FROM ida_func")
  if err != nil {
    log.Fatal(err)
  }

  curTable := combinedRows[:]
  leftUsed := make(map[*combinedRow]struct{})
  for rows.Next() {
    // read func
    var tmpFuncInfo funcInfo
    err = rows.Scan(&tmpFuncInfo.id, &tmpFuncInfo.sid, &tmpFuncInfo.addr)
    if err != nil {
      log.Fatal(err)
    }

    // left join
    /*
    saved := false
    for idx:=0; idx<len(curTable); idx++ {
      if curTable[idx].left.(*sample).id == tmpFuncInfo.sid {
        if !saved {
          funcInfos = append(funcInfos, tmpFuncInfo)
          saved = true
        }
        combinedRows = append(combinedRows, combinedRow{left: &curTable[idx], right: &funcInfos[len(funcInfos)-1]})
        leftUsed[idx] = struct{}{}
      }
    }
    */
    if subRows, exists := tableRBT.Get(tmpFuncInfo.sid); exists {
      saved := false
      for _, combinedRowAddr := range(subRows.([](*combinedRow))) {
        if !saved {
          funcInfos = append(funcInfos, tmpFuncInfo)
          saved = true
        }
        combinedRows = append(combinedRows, combinedRow{left: combinedRowAddr, right: &funcInfos[len(funcInfos)-1]})
        leftUsed[combinedRowAddr] = struct{}{}
      }
    }
  }

  // add not paired left data
  for idx:=0; idx<len(curTable); idx++ {
    if _, exists := leftUsed[&curTable[idx]]; !exists{
      combinedRows = append(combinedRows, combinedRow{left: &curTable[idx], right: nil})
    }
  }

  // delete tableRBT
  tableRBT.Clear()

  // update new table
  curTable = combinedRows[len(curTable):]
  log.Printf("Found %d rows.\n", len(curTable))

  PrintMemUsage()

  // group table
  log.Println("Group tables by id, group, and malicious.")
  // build rbtree for curTable
  tableRBT = rbt.NewWith(func(a, b interface{}) int {
    if a.(groupKey).id < b.(groupKey).id {
      return -1
    } else if a.(groupKey).id == b.(groupKey).id {
      if a.(groupKey).group < b.(groupKey).group {
        return -1
      } else if a.(groupKey).group == b.(groupKey).group {
        if a.(groupKey).mal == b.(groupKey).mal {
          return 0
        } else if a.(groupKey).mal {
          return 1
        } else {
          return -1
        }
      } else {
        return 1
      }
    } else {
      return 1
    }
  })

  groupRows := make([]groupRow, 0, 0)
  for idx:=0; idx<len(curTable); idx++ {
    tmpID := curTable[idx].left.(*combinedRow).left.(*sample).id
    tmpGroup := curTable[idx].left.(*combinedRow).left.(*sample).group
    tmpMal := curTable[idx].left.(*combinedRow).left.(*sample).mal
    key := groupKey{id: tmpID, group: tmpGroup, mal: tmpMal}

    if groupNode, exists := tableRBT.Get(key); !exists {
      groupRows = append(groupRows, groupRow{
        groupKey:   groupKey{
          id:     tmpID,
          group:  tmpGroup,
          mal:    tmpMal,
        },
        data:   make([](*combinedRow), 0, 0),
      })
      nodeRef := &groupRows[len(groupRows)-1]
      nodeRef.data = append(nodeRef.data, &curTable[idx])
      tableRBT.Put(key, nodeRef)
    } else {
      nodeRef := groupNode.(*groupRow)
      nodeRef.data = append(nodeRef.data, &curTable[idx])
    }
  }

  log.Printf("Group into %d rows.\n", len(groupRows))

  PrintMemUsage()

  // calculate function counts
  log.Println("Calculate function counts.")
  for idx:=0; idx<len(groupRows); idx++ {
    ida_set := make(map[int]struct{})
    r2_set := make(map[int]struct{})
    common_set := make(map[int]struct{})

    for _, rowRef := range(groupRows[idx].data) {
      r2_set[rowRef.left.(*combinedRow).right.(*funcInfo).id] = struct{}{}
      if rowRef.right != nil {
        ida_set[rowRef.right.(*funcInfo).id] = struct{}{}
        if rowRef.right.(*funcInfo).addr == rowRef.left.(*combinedRow).right.(*funcInfo).addr {
          common_set[rowRef.left.(*combinedRow).right.(*funcInfo).id] = struct{}{}
        }
      }
    }

    groupRows[idx].ida_func_count = len(ida_set)
    groupRows[idx].r2_func_count = len(r2_set)
    groupRows[idx].common_records_count = len(common_set)
  }

  PrintMemUsage()


  // sort
  log.Println("Sort by malicious and ida_func_count.")

  sort.Slice(groupRows, func(i, j int) bool {
    if groupRows[i].groupKey.mal != groupRows[j].groupKey.mal {
      return !groupRows[i].groupKey.mal
    }
    return groupRows[i].ida_func_count < groupRows[j].ida_func_count
  })

  log.Println("Task finished.")

  PrintMemUsage()

  // Print
  for idx:=0; idx<len(groupRows); idx++ {
    fmt.Println(groupRows[idx].id, groupRows[idx].group, groupRows[idx].mal, groupRows[idx].ida_func_count, groupRows[idx].r2_func_count, groupRows[idx].common_records_count)
  }
}
